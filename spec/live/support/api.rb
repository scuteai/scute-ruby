# frozen_string_literal: true

require "json"
require "net/http"
require "uri"

module ScuteLive
  # JSON over HTTP for what scute-ruby has no method for, and for the end
  # user's side (a browser or app signs in; scute-ruby runs on servers).
  # Secret-looking values in answers are remembered, so they're redacted
  # from the output.
  class Api
    class Failure < StandardError; end

    # Agent keys (scak_) and task tokens (sct_) are caught by their shape; "key" and "value" are too common to list.
    SENSITIVE = %w[access refresh csrf token secret backup_codes jws signature assertion provisioning_uri].freeze

    Response = Struct.new(:status, :body, :headers) do
      def ok? = status.between?(200, 299)
      def [](key) = body.is_a?(Hash) ? body[key] : nil
      def dig(*keys) = body.is_a?(Hash) ? body.dig(*keys) : nil

      # Never the body: it can hold tokens.
      def inspect = "#<response #{status}#{" #{self['error_code'] || self['error']}" if self['error']}>"
      alias_method :to_s, :inspect
    end

    def initialize(config)
      @base_url = config.base_url
      @secret = config.secret
      Redactor.remember(@secret)
    end

    # as: :secret (the app's API key), :public, [:bearer, token] (a task
    # token or an agent key) or [:session, access_token] (the user's own).
    def request(method, path, body: nil, as: :secret, headers: {})
      uri = URI("#{@base_url}#{path}")
      req = Net::HTTP.const_get(method.to_s.capitalize).new(uri)
      { "Accept" => "application/json", "Content-Type" => "application/json", "User-Agent" => "scute-ruby-live/#{Scute::VERSION}" }
        .merge(credentials(as)).merge(headers).each { |k, v| req[k] = v }
      req.body = JSON.generate(body) unless body.nil?
      res = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == "https", open_timeout: 10, read_timeout: 30) { |http| http.request(req) }
      parsed = parse(res.body)
      remember_secrets(parsed)
      Response.new(res.code.to_i, parsed, res.each_header.to_h)
    end

    %i[get post patch put delete].each do |verb|
      define_method(verb) { |path, **options| request(verb, path, **options) }

      # The answer's body, or a Failure naming the status and the API's error.
      define_method(:"#{verb}!") do |path, **options|
        res = request(verb, path, **options)
        raise Failure, "#{verb.upcase} #{path.split('?').first} answered #{res.status}#{error_of(res)}" unless res.ok?

        res.body
      end
    end

    private

    def credentials(as)
      case as
      in :secret then { "Authorization" => "Bearer #{@secret}" }
      in :public then {}
      in [:bearer, token] then { "Authorization" => "Bearer #{token}" }
      in [:session, access] then { "X-Authorization" => access }
      end
    end

    def parse(raw)
      return nil if raw.nil? || raw.empty?

      JSON.parse(raw)
    rescue JSON::ParserError
      raw
    end

    def error_of(res)
      return "" unless res["error"]

      ": #{res['error']}#{" (#{res['error_code']})" if res['error_code']}"
    end

    def remember_secrets(value)
      case value
      when Hash
        value.each do |k, v|
          SENSITIVE.include?(k) ? Redactor.remember(*Array(v).grep(String)) : remember_secrets(v)
        end
      when Array then value.each { |v| remember_secrets(v) }
      end
    end
  end
end
