ARG KONG_BASE_TAG
FROM kong${KONG_BASE_TAG}
USER root

ENV LUA_PATH /usr/local/share/lua/5.1/?.lua;/usr/local/kong-oidc/?.lua
# For lua-cjson
ENV LUA_CPATH /usr/local/lib/lua/5.1/?.so

# Install unzip for luarocks, gcc for lua-cjson
RUN apt update && apt install -y unzip gcc curl
RUN luarocks install luacov
RUN luarocks install luaunit
RUN luarocks install lua-cjson
RUN luarocks install luaossl OPENSSL_DIR=/usr/local/kong CRYPTO_DIR=/usr/local/kong

# Change openidc version when version in rockspec changes
RUN luarocks install lua-resty-openidc 1.7.6-3

WORKDIR /usr/local/kong-oidc

COPY . .
