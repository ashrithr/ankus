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

module Ankus
  module Util
    # Thread pool class (does not handle synchronization). Allows to perform:
    #   new(size) - creates a thread pool of a given size
    #   schedule(*args, &job) - schedules a new job to be executed
    #   shutdown - shuts down all threads (after they finish working)
    #
    # Usage:
    #   p = Pool.new(10)
    #   20.times do |i|
    #     p.schedule do
    #       sleep rand(4) + 2
    #       puts "Job #{i} finished by thread #{Thread.current[:id]}"
    #     end
    #   end
    #   p.shutdown
    class ThreadPool
      def initialize(size)
        @size = size
        @jobs = Queue.new

        @pool = Array.new(@size) do |i|
          Thread.new do
            Thread.current[:id] = i
            catch(:exit) do
              loop do
                job, args = @jobs.pop
                job.call(*args)
              end
            end
          end
        end
      end

      def schedule(*args, &block)
        @jobs << [block, args]
      end

      def shutdown
        @size.times do
          schedule { throw :exit }
        end
        @pool.map(&:join)
      end
    end
  end
end
