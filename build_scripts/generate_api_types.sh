#!/usr/bin/env bash
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$REPO_ROOT/src/api/generated"

# Step 1: Extract components/schemas from the OpenAPI 3.1 YAML and create a
# JSON Schema $defs document with a synthetic root that references ALL schemas.
# This ensures QuickType generates types for config, health, cache, and routing.
# Uses only Node.js tooling: npx js-yaml + node built-ins. Tool versions are
# pinned: an unpinned quicktype (26.x) rewrites the whole header differently.
# QuickType names the root type after the output file, so the file name is
# fixed (inside a private temp dir) to keep the generated header reproducible.
GEN_TMP="$(mktemp -d /tmp/keen-pbr-gen-XXXXXX)"
SCHEMA_TMP="$GEN_TMP/keen-pbr-schema.json"
TYPES_TMP="$GEN_TMP/keen-pbr-types.hpp"
trap 'rm -rf "$GEN_TMP"' EXIT

npx --yes js-yaml@4.1.0 "$REPO_ROOT/docs/openapi.yaml" \
  | node -e "
let d = '';
process.stdin.on('data', c => d += c);
process.stdin.on('end', () => {
  const spec = JSON.parse(d);
  const schemas = spec.components.schemas;

  // Remove OpenAPI-specific extensions that QuickType does not understand
  function clean(obj) {
    if (typeof obj !== 'object' || obj === null) return;
    if (Array.isArray(obj)) { obj.forEach(clean); return; }
    delete obj.discriminator;
    delete obj.example;
    delete obj.description;
    Object.values(obj).forEach(clean);
  }
  clean(schemas);

  // Rewrite \$ref paths from OpenAPI to JSON Schema \$defs format
  function rewriteRefs(obj) {
    if (typeof obj !== 'object' || obj === null) return;
    if (Array.isArray(obj)) { obj.forEach(rewriteRefs); return; }
    if (obj['\$ref']) {
      obj['\$ref'] = obj['\$ref'].replace('#/components/schemas/', '#/\$defs/');
    }
    Object.values(obj).forEach(rewriteRefs);
  }
  rewriteRefs(schemas);

  // Synthetic root: reference ALL schemas so QuickType generates every type.
  // Each schema becomes a property of the root, driving code generation.
  const rootProperties = {};
  for (const name of Object.keys(schemas)) {
    rootProperties[name] = { '\$ref': '#/\$defs/' + name };
  }

  const jsonSchema = {
    '\$schema': 'http://json-schema.org/draft-07/schema#',
    '\$defs': schemas,
    'type': 'object',
    'properties': rootProperties
  };

  process.stdout.write(JSON.stringify(jsonSchema, null, 2));
});
" > "$SCHEMA_TMP"

# Step 2: Run QuickType to generate C++ types
npx --yes quicktype@23.2.6 \
  --lang cpp \
  --src "$SCHEMA_TMP" \
  --src-lang schema \
  --namespace keen_pbr3::api \
  --no-boost \
  --code-format with-struct \
  -o "$TYPES_TMP"

# Step 3: Post-process: fix include path and prepend required system headers
node -e "
const fs = require('fs');
let content = fs.readFileSync('$TYPES_TMP', 'utf8');

// Fix nlohmann include path
content = content.replace('#include \"json.hpp\"', '#include <nlohmann/json.hpp>');

// Add cstdint and map includes (QuickType omits them)
content = content.replace(
  '#include <optional>',
  '#include <cstdint>\n#include <map>\n#include <optional>'
);

// Add generation comment at the top
const header = '// Generated from docs/openapi.yaml via build_scripts/generate_api_types.sh\n' +
               '// Run \"make generate\" to regenerate (requires Node.js).\n\n';
content = header + content;

fs.writeFileSync('$REPO_ROOT/src/api/generated/api_types.hpp', content);
"
