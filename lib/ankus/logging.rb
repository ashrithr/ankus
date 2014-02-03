# Copyright 2013, Cloudwick, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Monkey patches log4r to print colored levels
require 'log4r'

original_verbosity = $VERBOSE
$VERBOSE = nil
module Log4r
  class PatternFormatter
    DirectiveTable = {
        'c' => 'event.name',
        'C' => 'event.fullname',
        'd' => 'format_date',
        'g' => 'Log4r::GDC.get()',
        't' => '(event.tracer.nil? ? "no trace" : event.tracer[0])',
        'T' => '(event.tracer.nil? ? "no trace" : event.tracer[0].split(File::SEPARATOR)[-1])',
        'm' => 'event.data',
        'h' => '(Thread.current[:name] or Thread.current.to_s)',
        'p' => 'Process.pid.to_s',
        'M' => 'format_object(event.data)',
        'l' => 'LNAMES[event.level]',
        'L' => %q|case LNAMES[event.level]
                when "ERROR"
                  "#{LNAMES[event.level]}".red + " ::"
                when "WARN"
                  "#{LNAMES[event.level][0..3]} ".yellow + " ::"
                when "INFO"
                  "#{LNAMES[event.level][0..3]} ".blue + " ::"
                when "DEBUG"
                  "#{LNAMES[event.level]}".cyan + " ::"
                when "FATAL"
                  "#{LNAMES[event.level]}".red + " ::"
                else
                  LNAMES[event.level][0..3]
                end|,
        'x' => 'Log4r::NDC.get()',
        'X' => 'Log4r::MDC.get("DTR_REPLACE")',
        '%' => '"%"'
    }
    DirectiveRegexp = /([^%]*)((%-?\d*(\.\d+)?)([cCdgtTmhpMlLxX%]))?(\{.+?\})?(.*)/
  end
end
$VERBOSE = original_verbosity