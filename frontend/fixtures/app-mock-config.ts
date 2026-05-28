import type { ConfigObject } from "../src/api/generated/model/configObject"

/** Shared demo/e2e config payload (single source for mock API state). */
export function createAppMockConfig(): ConfigObject {
  return {
    daemon: {
      strict_enforcement: false,
      firewall_backend: "auto",
    },
    lists: {
      shared_list: {
        url: "https://example.com/list.txt",
        domains: ["example.com", "*.example.com"],
      },
      other_list: {
        domains: ["other.example"],
      },
      blocked: {
        ip_cidrs: ["10.0.0.0/8"],
      },
    },
    outbounds: [
      {
        type: "interface",
        tag: "wan0",
        interface: "ppp0",
      },
      {
        type: "interface",
        tag: "vpn0",
        interface: "tun0",
      },
      {
        type: "ignore",
        tag: "drop",
      },
    ],
    route: {
      rules: [
        {
          enabled: true,
          outbound: "wan0",
          list: ["shared_list"],
          dest_addr: "10.0.0.0/8",
        },
        {
          enabled: true,
          outbound: "drop",
          list: ["shared_list"],
          proto: "udp",
        },
        {
          enabled: false,
          outbound: "vpn0",
          list: ["blocked"],
        },
      ],
    },
  }
}

export function createAppMockListRefreshState() {
  return {
    shared_list: {
      last_refresh_ts: Math.floor(Date.now() / 1000) - 3600,
      content_hash: "mock-shared",
    },
  }
}

/** Runtime interfaces payload for Playwright (distinct names for assertions). */
export const E2E_RUNTIME_INTERFACES = {
  interfaces: [
    {
      name: "e2e_wan",
      status: "up",
      admin_up: true,
      oper_state: "up",
      carrier: true,
      ipv4_addresses: ["192.0.2.10/24", "192.0.2.11/24", "192.0.2.12/24"],
      ipv6_addresses: ["2001:db8::1/64", "2001:db8::2/64"],
    },
  ],
} as const
