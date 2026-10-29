# frozen_string_literal: true

require "ipaddr"

module Scute
  # The end user's IP address, passed to Scute on calls made with the app's
  # secret key as the X-Scute-Client-IP header. Scute checks it against the
  # workspace's IP rules on the sign-ins your server starts or completes, and
  # uses it as the person's address for sessions and audit events. Without
  # it, a server-started sign-in isn't checked against IP rules.
  #
  #   scute = Scute::Client.new(client_ip: request.remote_ip)
  #   scute.with_client_ip(request.remote_ip).authz.start_step_up(...)
  #   Scute::ClientIP.with(request.remote_ip) { scute.users.create(email) }
  #
  # Scute takes one address (IPv4 or IPv6), never a range or a list.
  module ClientIP
    HEADER = "X-Scute-Client-IP"
    KEY = :scute_client_ip
    private_constant :KEY

    module_function

    # The address, trimmed, or nil when the value isn't one IP address (blank,
    # a range, a list or anything else).
    def parse(value)
      text = value.to_s.strip
      return nil if text.empty? || text.include?("/")

      IPAddr.new(text)
      text
    rescue ArgumentError # IPAddr::InvalidAddressError and friends
      nil
    end

    # Like parse, for a value you passed on purpose: nil and blank mean "no
    # address", anything else that isn't one IP address raises ArgumentError.
    def parse!(value)
      return nil if value.nil? || value.to_s.strip.empty?

      parse(value) or raise ArgumentError, "client_ip must be one IP address (IPv4 or IPv6), got #{value.inspect}"
    end

    # The address for calls made in this block by any client that wasn't
    # given one. Scute::ClientIP::Middleware sets it for each request.
    def with(value)
      previous = Thread.current[KEY]
      Thread.current[KEY] = parse!(value)
      yield
    ensure
      Thread.current[KEY] = previous
    end

    # The address set by with (or the middleware) for this request, or nil.
    def current = Thread.current[KEY]

    # The address of the person behind a Rack or Rails request, or nil. Rails:
    # request.remote_ip, which honors config.action_dispatch.trusted_proxies.
    # Rack: Rack::Request#ip, which skips Rack's trusted proxies. Never reads
    # X-Forwarded-For itself.
    def from_request(request)
      return nil if request.nil?

      ip = if request.respond_to?(:remote_ip) then request.remote_ip
           elsif request.respond_to?(:ip) then request.ip
           end
      parse(ip)
    end

    # The address from a Rack env: the one Rails' RemoteIp middleware worked
    # out when it ran, otherwise Rack::Request#ip.
    def from_env(env)
      return parse(env["action_dispatch.remote_ip"].to_s) if env["action_dispatch.remote_ip"]

      require "rack/request"
      parse(Rack::Request.new(env).ip)
    rescue LoadError
      parse(env["REMOTE_ADDR"])
    end

    # Rack middleware: every Scute client used while handling a request (one
    # you made once at boot too) passes that request's address, unless the
    # client was given one.
    #
    #   # config/application.rb (after ActionDispatch::RemoteIp, so trusted proxies apply)
    #   config.middleware.use Scute::ClientIP::Middleware
    #   # config.ru
    #   use Scute::ClientIP::Middleware
    class Middleware
      def initialize(app)
        @app = app
      end

      def call(env)
        ClientIP.with(ClientIP.from_env(env)) { @app.call(env) }
      end
    end
  end
end
