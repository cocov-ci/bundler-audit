FROM ruby:3.1-alpine

RUN apk add --no-cache git openssh

RUN gem install cocov_plugin_kit -v 0.1.2
RUN gem install bundler-audit

COPY plugin.rb /plugin.rb

CMD ["cocov", "/plugin.rb"]
