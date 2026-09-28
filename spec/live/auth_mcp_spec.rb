# frozen_string_literal: true

require_relative "live_helper"

# Scute's auth MCP server, as a voice or chat platform uses it: JSON-RPC over
# HTTP with the agent's key. scute-ruby has no MCP client and no agent key or
# conversation methods, so those go over HTTP too.
RSpec.describe "Live: auth MCP (JSON-RPC over HTTP, agent key)", :live, order: :defined do
  before(:context) do
    agent = world.agent("support")
    # POST /v1/apps/:app_id/authz/agents/:slug/keys (the key is shown once).
    key = api.post!(world.apps("/authz/agents/#{agent['slug']}/keys"), body: { name: "#{world.prefix} mcp" })
    @mcp = { slug: agent["slug"], key: key["key"], person: world.user(:caller, roles: ["billing"]),
             conversation: "#{world.prefix}-conversation", next_id: 0 }
  end

  def rpc(method, params = nil, notification: false)
    body = { jsonrpc: "2.0", method: method }
    body[:id] = (@mcp[:next_id] += 1) unless notification
    body[:params] = params if params
    headers = { "Accept" => "application/json, text/event-stream" }
    headers["Mcp-Session-Id"] = @mcp[:session] if @mcp[:session]
    res = api.post("/v1/mcp/auth/#{app_id}", body: body, as: [:bearer, @mcp[:key]], headers: headers)
    @mcp[:session] ||= res.headers["mcp-session-id"]
    res
  end

  def tool(name, arguments)
    res = rpc("tools/call", { name: name, arguments: arguments })
    expect(res.status).to eq(200)
    res.dig("result", "structuredContent")
  end

  def conversation(rest = "") = world.apps("/authz/agents/#{@mcp[:slug]}/conversations/#{@mcp[:conversation]}#{rest}")

  it "initializes a session" do
    res = rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "scute-ruby-live", version: "1" } })

    expect(res.status).to eq(200)
    expect(res.dig("result", "serverInfo", "name")).to eq("scute-auth")
    expect(res.dig("result", "protocolVersion")).to eq("2025-06-18")
    expect(@mcp[:session]).to start_with("mcp_")
    expect(rpc("notifications/initialized", notification: true).status).to eq(202)
  end

  it "lists the tools" do
    names = rpc("tools/list").dig("result", "tools").map { |t| t["name"] }

    expect(names).to include("scute_identify", "scute_submit_code", "scute_check", "scute_whoami")
  end

  it "identifies the person by a test email, linked to the platform's conversation id" do
    answer = tool("scute_identify", { email: @mcp[:person]["email"], conversation_id: @mcp[:conversation] })

    expect(answer).to include("status" => "code_sent")
    expect(answer["say"]).to include("***@example.com")
  end

  it "verifies them with the code they read out (424242)" do
    expect(tool("scute_submit_code", { code: ScuteLive::World::CODE })).to include("status" => "verified")
  end

  it "checks what the agent may do for them" do
    expect(tool("scute_check", { action: "read", resource: "invoice:INV-1" })).to include("decision" => "allow")
    refused = tool("scute_check", { action: "delete", resource: "account:1" })
    expect(refused).to include("decision" => "deny", "say" => "I'm not able to do that.")
  end

  # GET and POST /v1/apps/:app_id/authz/agents/:slug/conversations/:conversation_id(/check)
  it "lets the app's backend look the conversation up and check for it" do
    found = api.get!(conversation)
    expect(found).to include("verified" => true, "ended" => false)
    expect(found["person"]).to include("app_user_id" => @mcp[:person]["id"], "email" => @mcp[:person]["email"])

    expect(api.post!(conversation("/check"), body: { action: "read", resource: "invoice:INV-2" })).to include("decision" => "allow")
    expect(api.post!(conversation("/check"), body: { action: "delete", resource: "account:1" }))
      .to include("decision" => "deny", "reason" => "agent_role")
  end

  it "ends the conversation (DELETE)" do
    ended = api.delete("/v1/mcp/auth/#{app_id}", as: [:bearer, @mcp[:key]], headers: { "Mcp-Session-Id" => @mcp[:session].to_s })

    expect(ended.status).to eq(204)
    expect(api.get!(conversation)).to include("ended" => true)
  end
end
