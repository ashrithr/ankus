module Ankus
  module Errors
    class Error < StandardError
      attr_accessor :verbose

      def self.slurp(error, message=nil)
        new_error = new(message)
        new_error.set_backtrace(error.backtrace)
        new_error.verbose = error.message
        new_error
      end
    end
    class NotImplemented < Ankus::Errors::Error; end
    class ParseError < Ankus::Errors::Error; end
    class ParseError::NoKey < Ankus::Errors::Error; end
  end
end
