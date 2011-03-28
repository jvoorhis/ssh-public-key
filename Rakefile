require 'rake/testtask'

Rake::TestTask.new do |t|
  t.libs = %w( lib test )
  t.test_files = Rake::FileList['test/*_test.rb']
end

task :default => :test
