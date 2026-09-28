# frozen_string_literal: true

require "json"
require "openssl"

module Scute
  # A verified access token: who the user is, and whether someone else is
  # signed in as them (support access).
  Session = Data.define(:user_id, :app_id, :workspace_id, :expires_at, :actor, :claims) do
    def impersonated? = claims["imp"] == true

    # Context for authorization checks made for this request: a permission
    # marked "not while impersonating" is refused when someone is signed in
    # as the user.
    def authz_context = impersonated? ? { "impersonated" => true, "actor" => actor || "unknown" } : {}
  end

  # Verifies your users' access tokens locally with the app's signing keys
  # (RS256, from the app's JWKS). Local verification can't see a session that
  # was revoked a moment ago: pass remote: true where that matters (it asks
  # Scute, one call).
  #
  #   session = scute.tokens.verify(token)   # raises Scute::InvalidToken
  #   session.user_id
  class Tokens
    KEYS_TTL = 600     # re-read the keys every 10 minutes
    REFETCH_AFTER = 60 # on an unknown key, re-read at most once a minute
    LEEWAY = 30        # seconds of clock skew allowed on exp
    ALGORITHMS = %w[RS256].freeze

    def initialize(client, clock: -> { Time.now })
      @client = client
      @clock = clock
      @lock = Mutex.new
      @keys = nil
      @fetched_at = nil
      @public_app_id = nil
    end

    def verify(token, remote: false)
      raise InvalidToken.new("No access token", :missing) if token.to_s.empty?

      header, claims, signed, signature = decode(token.to_s)
      raise InvalidToken.new("Unexpected token algorithm #{header['alg'].inspect}", :algorithm) unless ALGORITHMS.include?(header["alg"])

      verify_signature!(header, signed, signature)
      session = check_claims!(claims)
      confirm_live!(token) if remote
      session
    end

    # The id the app's tokens carry (aid): the app's public id ("app_...").
    def public_app_id
      @lock.synchronize do
        @public_app_id ||= if @client.app_id.start_with?("app_")
                             @client.app_id
                           else
                             @client.user_request(:get, @client.apps_path).fetch("id")
                           end
      end
    end

    private

    def decode(token)
      parts = token.split(".")
      raise InvalidToken.new("Not a JWT", :malformed) unless parts.size == 3

      header = JSON.parse(b64(parts[0]))
      claims = JSON.parse(b64(parts[1]))
      raise InvalidToken.new("Not a JWT", :malformed) unless header.is_a?(Hash) && claims.is_a?(Hash)

      [header, claims, "#{parts[0]}.#{parts[1]}", b64(parts[2])]
    rescue JSON::ParserError, ArgumentError
      raise InvalidToken.new("Not a JWT", :malformed)
    end

    def verify_signature!(header, signed, signature)
      return if matching_keys(header).any? { |key| key.verify("SHA256", signature, signed) }
      # The keys may have rotated since the last read.
      return if refetch_allowed? && matching_keys(header, refresh: true).any? { |key| key.verify("SHA256", signature, signed) }

      raise InvalidToken.new("The token's signature doesn't match the app's keys", :signature)
    end

    def check_claims!(claims)
      exp = claims["exp"]
      raise InvalidToken.new("The token has no expiry", :malformed) unless exp.is_a?(Numeric)
      raise InvalidToken.new("The token has expired", :expired) if exp + LEEWAY < @clock.call.to_i
      raise InvalidToken.new("The token is for another app", :wrong_app) unless claims["aid"] == public_app_id
      raise InvalidToken.new("Not a user's session", :not_a_user) if claims["m2m"] || claims["uuid"].to_s.empty?

      Session.new(user_id: claims["uuid"], app_id: claims["aid"], workspace_id: claims["wid"], expires_at: Time.at(exp),
                  actor: claims["imp"] == true ? claims["act"] : nil, claims: claims)
    end

    def confirm_live!(token)
      @client.sessions.current_user(token)
    rescue APIError => e
      raise unless [401, 403, 404].include?(e.status)

      raise InvalidToken.new("The session has ended", :revoked)
    end

    def matching_keys(header, refresh: false)
      keys = signing_keys(refresh: refresh)
      kid = header["kid"]
      return keys.values if kid.nil?

      keys.key?(kid) ? [keys[kid]] : []
    end

    def signing_keys(refresh: false)
      @lock.synchronize do
        stale = @fetched_at.nil? || @clock.call - @fetched_at > KEYS_TTL
        if refresh || stale || @keys.nil?
          @keys = fetch_keys
          @fetched_at = @clock.call
        end
        @keys
      end
    end

    def refetch_allowed?
      @lock.synchronize { @fetched_at.nil? || @clock.call - @fetched_at > REFETCH_AFTER }
    end

    def fetch_keys
      data = @client.user_request(:get, @client.auth_path("/.well-known/jwks.json"))
      Array(data && data["keys"]).each_with_index.with_object({}) do |(jwk, i), out|
        next unless jwk["kty"] == "RSA" && (jwk["alg"].nil? || ALGORITHMS.include?(jwk["alg"]))

        out[jwk["kid"] || "key#{i}"] = rsa_key(jwk)
      end
    end

    def rsa_key(jwk)
      n = OpenSSL::BN.new(b64(jwk["n"]), 2)
      e = OpenSSL::BN.new(b64(jwk["e"]), 2)
      rsa = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(n), OpenSSL::ASN1::Integer(e)])
      spki = OpenSSL::ASN1::Sequence([
                                       OpenSSL::ASN1::Sequence([OpenSSL::ASN1::ObjectId("rsaEncryption"), OpenSSL::ASN1::Null(nil)]),
                                       OpenSSL::ASN1::BitString(rsa.to_der)
                                     ])
      OpenSSL::PKey::RSA.new(spki.to_der)
    end

    # base64url without the base64 gem (it isn't a default gem from Ruby 3.4).
    # "m0" is strict, like Base64.urlsafe_decode64: bad input raises ArgumentError.
    def b64(value)
      s = value.to_s.tr("-_", "+/")
      (s + ("=" * ((4 - (s.length % 4)) % 4))).unpack1("m0")
    end
  end
end
