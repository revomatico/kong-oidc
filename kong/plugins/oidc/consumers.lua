local workspaces = require "kong.workspaces"

local consumers = {}


-- the following fuctions are to support custom_id loading. based off the following:
-- https://github.com/Kong/kong/blob/25da4623da80116bf4eece365313329da53d45f8/kong/runloop/events.lua#L280C16-L280C38
-- https://github.com/Kong/kong/blob/25da4623da80116bf4eece365313329da53d45f8/kong/pdk/client.lua#L183
local function load_consumer_by_custom_id(custom_id)
    return kong.db.consumers:select_by_custom_id(custom_id)
end

-- function to support cache invalidation of custom_id
local function crud_consumers_custom_id_handler(data)
    workspaces.set_workspace(data.workspace)

    ngx.log(ngx.NOTICE, "consumer event received, invalidating cache for custom_id")

    local old_entity = data.old_entity
    local old_custom_id
    if old_entity then
        old_custom_id = old_entity.custom_id
        if old_custom_id and old_custom_id ~= ngx.null and old_custom_id ~= "" then
            kong.cache:invalidate(kong.db.consumers:cache_key(old_custom_id))
        end
    end

    local entity = data.entity
    if entity then
        local custom_id = entity.custom_id
        if custom_id and custom_id ~= ngx.null and custom_id ~= "" and custom_id ~= old_custom_id then
            kong.cache:invalidate(kong.db.consumers:cache_key(custom_id))
        end
    end
end

-- Consumers invalidation
-- As we support conifg.consumer_by to be configured as Consumer.custom_id,
-- so add an event handler to invalidate the extra cache in case of data inconsistency
function consumers.register_events()
    kong.worker_events.register(crud_consumers_custom_id_handler, "crud", "consumers")
end

-- get consumer with key as defined by the 'consumer_by'
-- possible values (see schema.lua): 'id_or_username', 'custom_id', if not provided or unknown defaults to 'id_or_username'
function consumers.get_consumer_by(key, consumer_by)
    ngx.log(ngx.DEBUG, "OidcHandler.consumers getting consumer " .. key .. " by " .. consumer_by)
    if consumer_by and consumer_by == "custom_id" then
        return consumers.get_consumer_by_custom_id(key)
    end

    return consumers.get_consumer_by_id_or_username(key)
end

function consumers.get_consumer_by_id_or_username(key)
    if not key or type(key) ~= "string" then
        error("key must be a string", 2)
    end
    local cache_key = kong.db.consumers:cache_key(key)
    return kong.cache:get(cache_key, nil, kong.client.load_consumer, key, true)
end

function consumers.get_consumer_by_custom_id(custom_id)
    if not custom_id or type(custom_id) ~= "string" then
        error("key must be a string", 2)
    end
    local cache_key = kong.db.consumers:cache_key(custom_id)
    return kong.cache:get(cache_key, nil, load_consumer_by_custom_id, custom_id)
end

return consumers
