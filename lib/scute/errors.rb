# frozen_string_literal: true

module Scute
  class Error < StandardError; end

  # Scute answered with an error (4xx/5xx). `code` is the API's error_code.
  class APIError < Error
    attr_reader :status, :code

    def initialize(message, status: nil, code: nil)
      super(message)
      @status = status
      @code = code
    end
  end

  # Scute couldn't be reached (connection refused, timeout, DNS).
  class ConnectionError < Error; end

  # Something is missing to make the call (app id, secret key, a task token).
  class ConfigurationError < Error; end
end
