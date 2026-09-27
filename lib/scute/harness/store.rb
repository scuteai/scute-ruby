# frozen_string_literal: true

module Scute
  class Harness
    # Run state in this process: fine for one server and for tests. With more
    # than one process, use CacheStore over Rails.cache (Redis, Memcached, Solid Cache).
    class MemoryStore
      def initialize
        @data = {}
        @lock = Mutex.new
      end

      def get(key)
        @lock.synchronize do
          value, until_at = @data[key]
          next nil unless value
          next(@data.delete(key) && nil) if until_at && until_at < Time.now.to_f

          value
        end
      end

      def set(key, value, ttl = nil)
        @lock.synchronize { @data[key] = [value, ttl ? Time.now.to_f + ttl : nil] }
      end
    end

    # Any ActiveSupport::Cache store (Rails.cache).
    class CacheStore
      def initialize(cache)
        @cache = cache
      end

      def get(key) = @cache.read(key)

      def set(key, value, ttl = nil)
        ttl ? @cache.write(key, value, expires_in: ttl) : @cache.write(key, value)
      end
    end
  end
end
