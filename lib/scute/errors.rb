# frozen_string_literal: true

module Scute
  class Error < StandardError; end

  # Scute answered with an error (4xx/5xx). `code` is the API's error_code.
  class APIError < Error
    # body: the API's answer, when it sent one.
    attr_reader :status, :code, :body

    def initialize(message, status: nil, code: nil, body: nil)
      super(message)
      @status = status
      @code = code
      @body = body
    end
  end

  # Scute couldn't be reached (connection refused, timeout, DNS).
  class ConnectionError < Error; end

  # Something is missing to make the call (app id, secret key, a task token).
  class ConfigurationError < Error; end

  # An access token that isn't a live session of this app. `reason`:
  # :missing, :malformed, :algorithm, :signature, :expired, :wrong_app,
  # :not_a_user, :revoked.
  class InvalidToken < Error
    attr_reader :reason

    def initialize(message, reason)
      super(message)
      @reason = reason
    end
  end
end
