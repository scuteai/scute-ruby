# frozen_string_literal: true

module Scute
  module Agents
    # Register the agents you build and start tasks for them (secret key).
    # The agent itself runs with a task token; see Scute::Harness.
    class API
      def initialize(client)
        @client = client
      end

      def list = Array(@client.request(:get, path)["agents"])
      def get(slug) = @client.request(:get, path("/#{@client.esc(slug)}"))

      # roles: role slugs from your policy, the agent's ceiling. owner_user_id: a person
      # who can reach the app's workspace, answerable for the agent.
      def create(slug:, owner_user_id:, name: nil, description: nil, roles: nil, team_role: nil, settings: nil)
        body = { slug: slug, name: name, description: description, owner_user_id: owner_user_id,
                 roles: roles, team_role: team_role, settings: settings }.compact
        @client.request(:post, path, body: body)
      end

      def update(slug, **attrs) = @client.request(:patch, path("/#{@client.esc(slug)}"), body: attrs)
      def delete(slug) = @client.request(:delete, path("/#{@client.esc(slug)}"))

      # The kill switch: every open task ends at once.
      def suspend(slug) = @client.request(:post, path("/#{@client.esc(slug)}/suspend"))
      def resume(slug) = @client.request(:post, path("/#{@client.esc(slug)}/resume"))

      # status: "open" for live tasks only.
      def tasks(slug, status: nil)
        query = status ? "?status=#{@client.esc(status)}" : ""
        Array(@client.request(:get, path("/#{@client.esc(slug)}/tasks#{query}"))["tasks"])
      end

      # Start a task. The response carries the task token once (`token`); hand it
      # to the agent and never to the model.
      def start_task(slug, acts_for: nil, actions: nil, resources: nil, requester: nil, ttl: nil, ref: nil, parent_task_id: nil)
        body = { acts_for: acts_for, actions: actions, resources: resources, requester: requester,
                 ttl_seconds: ttl, ref: ref, parent_task_id: parent_task_id }.compact
        @client.request(:post, path("/#{@client.esc(slug)}/tasks"), body: body)
      end

      def complete_task(slug, id) = @client.request(:post, task_path(slug, id, "/complete"))
      def revoke_task(slug, id) = @client.request(:post, task_path(slug, id, "/revoke"))

      # The delegation as a signed JWT (sub: the person, act: the agent chain, RFC 8693).
      def assertion(slug, id) = @client.request(:get, task_path(slug, id, "/assertion"))

      private

      def path(rest = "") = @client.apps_path("/authz/agents#{rest}")
      def task_path(slug, id, rest) = path("/#{@client.esc(slug)}/tasks/#{@client.esc(id)}#{rest}")
    end
  end
end
