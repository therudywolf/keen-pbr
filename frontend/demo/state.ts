import type { ConfigObject } from "../src/api/generated/model/configObject"
import {
  createAppMockConfig,
  createAppMockListRefreshState,
} from "../fixtures/app-mock-config"

export type DemoConfigState = {
  config: ConfigObject
  /** Last applied config, restored by a discard. */
  saved_config: ConfigObject
  is_draft: boolean
  list_refresh_state: Record<
    string,
    { last_refresh_ts?: number; content_hash?: string }
  >
}

export function createInitialDemoState(): DemoConfigState {
  const config = createAppMockConfig()
  return {
    is_draft: false,
    list_refresh_state: createAppMockListRefreshState(),
    config,
    saved_config: config,
  }
}

let demoState = createInitialDemoState()

export function getDemoState(): DemoConfigState {
  return demoState
}

export function replaceDemoConfig(config: ConfigObject) {
  demoState = {
    ...demoState,
    config,
    is_draft: true,
  }
}

export function applyDemoConfig() {
  demoState = {
    ...demoState,
    saved_config: demoState.config,
    is_draft: false,
  }
}

export function discardDemoConfig(): boolean {
  if (!demoState.is_draft) {
    return false
  }
  demoState = {
    ...demoState,
    config: demoState.saved_config,
    is_draft: false,
  }
  return true
}

export function resetDemoState() {
  demoState = createInitialDemoState()
}
