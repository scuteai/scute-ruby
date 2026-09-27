# frozen_string_literal: true

require "json"
require "net/http"
require "uri"

module Scute
  # JSON over HTTP with a bearer token. The transport is swappable: anything
  # that responds to call(method, url, headers, body) and returns [status, body].
  class HTTP
    NETWORK_ERRORS = [
      Errno::ECONNREFUSED, Errno::ECONNRESET, Errno::EHOSTUNREACH, Errno::ETIMEDOUT,
      Net::OpenTimeout, Net::ReadTimeout, SocketError, EOFError, OpenSSL::SSL::SSLError
    ].freeze

    METHODS = {
      get: Net::HTTP::Get, post: Net::HTTP::Post, patch: Net::HTTP::Patch, put: Net::HTTP::Put, delete: Net::HTTP::Delete
    }.freeze

    attr_reader :base_url

    def initialize(base_url:, transport: nil, open_timeout: 5, read_timeout: 10, retries: 1)
      @base_url = base_url.to_s.sub(%r{/+\z}, "")
      @open_timeout = open_timeout
      @read_timeout = read_timeout
      @retries = retries
      @transport = transport || method(:net_http)
    end

    # idempotent: retry once on a network error (reads and checks, never a mint).
    def request(method, path, bearer:, body: nil, idempotent: method == :get)
      raise ConfigurationError, "No credentials for this Scute call" if bearer.to_s.empty?

      headers = {
        "Authorization" => "Bearer #{bearer}", "Accept" => "application/json",
        "Content-Type" => "application/json", "User-Agent" => "scute-ruby/#{VERSION}"
      }
      payload = body.nil? ? nil : JSON.generate(body)
      status, raw = send_with_retries(method, "#{@base_url}#{path}", headers, payload, idempotent)
      data = parse(raw)
      return data if status.between?(200, 299)

      hash = data.is_a?(Hash) ? data : {}
      message = hash["error"] || hash["say"] || "Scute answered #{status}"
      raise APIError.new(message, status: status, code: hash["error_code"], body: data)
    end

    private

    def send_with_retries(method, url, headers, payload, idempotent)
      attempts = 0
      begin
        @transport.call(method, url, headers, payload)
      rescue *NETWORK_ERRORS => e
        attempts += 1
        retry if idempotent && attempts <= @retries
        raise ConnectionError, "Couldn't reach Scute: #{e.class}: #{e.message}"
      end
    end

    def parse(raw)
      return nil if raw.nil? || raw.empty?

      JSON.parse(raw)
    rescue JSON::ParserError
      nil
    end

    def net_http(method, url, headers, payload)
      uri = URI(url)
      Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == "https",
                                          open_timeout: @open_timeout, read_timeout: @read_timeout) do |http|
        req = METHODS.fetch(method).new(uri)
        headers.each { |k, v| req[k] = v }
        req.body = payload if payload
        res = http.request(req)
        [res.code.to_i, res.body]
      end
    end
  end
end
