# frozen_string_literal: true

require "json"

module ScuteLive
  # A tiny Rack app with scute-ruby's controller concerns, driven with
  # Rack::MockRequest (no server):
  #
  #   GET /me                    who is signed in (?remote=1 asks Scute too)
  #   GET /accounts/:id/delete   scute_authorize!("delete", "account:<id>")
  class RackApp
    class Controller
      include Scute::Authentication
      include Scute::Authorization

      attr_reader :request, :scute_client

      def initialize(request, client)
        @request = request
        @scute_client = client
      end
    end

    def initialize(client)
      @client = client
    end

    def call(env)
      request = Rack::Request.new(env)
      controller = Controller.new(request, @client)
      controller.scute_authenticate!(remote: request.params["remote"] == "1")
      body = { "user_id" => controller.scute_user_id, "impersonated" => controller.scute_session.impersonated? }
      if (account = request.path_info[%r{\A/accounts/([^/]+)/delete\z}, 1])
        body["reason"] = controller.scute_authorize!("delete", "account:#{account}").reason
      end
      respond(200, body)
    rescue Scute::Unauthenticated => e
      respond(401, "error" => e.reason.to_s)
    rescue Scute::Forbidden => e
      respond(403, "error" => e.decision.reason)
    end

    # [status, parsed body]
    def get(path, headers = {})
      require "rack"
      res = Rack::MockRequest.new(self).get(path, headers)
      [res.status, JSON.parse(res.body)]
    end

    private

    def respond(status, body) = [status, { "content-type" => "application/json" }, [JSON.generate(body)]]
  end
end
