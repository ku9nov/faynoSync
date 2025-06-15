-- Telemetry aggregation script
-- Args:
-- 1: admin name
-- 2: date range (JSON array of dates)
-- 3: app name (or '*' for all apps)
-- 4: filter channels (JSON array)
-- 5: filter platforms (JSON array)
-- 6: filter architectures (JSON array)
-- 7: debug mode (boolean)

local admin = ARGV[1]
local date_range = cjson.decode(ARGV[2])
local app_name = ARGV[3]
local filter_channels = cjson.decode(ARGV[4])
local filter_platforms = cjson.decode(ARGV[5])
local filter_architectures = cjson.decode(ARGV[6])
local debug_mode = ARGV[7] == "true"

-- Helper function for debug logging with TTL
local function debug_log(key, value)
    if debug_mode then
        redis.call('SET', key, value, 'EX', 300) -- 300 seconds = 5 minutes
    end
end

-- Debug: Log input parameters
debug_log('debug:input_params', cjson.encode({
    admin = admin,
    date_range = date_range,
    app_name = app_name,
    filter_channels = filter_channels,
    filter_platforms = filter_platforms,
    filter_architectures = filter_architectures
}))

-- Initialize result structure
local result = {
    total_requests = 0,
    unique_clients = 0,
    clients_using_latest_version = 0,
    clients_outdated = 0,
    total_active_apps = 0,
    daily_stats = {},
    versions = {
        known_versions = {},
        usage = {},
        used_versions_count = 0
    },
    platforms = {},
    architectures = {},
    channels = {}
}

-- Helper function to check if value is in array
local function in_array(arr, val)
    -- Check if array is empty (no filters)
    if type(arr) ~= "table" or next(arr) == nil then
        return true
    end
    -- Check if value exists in array
    for _, v in ipairs(arr) do
        if v == val then
            return true
        end
    end
    return false
end

-- Helper function to check if version is already in known versions
local function version_exists(versions, version)
    for _, v in ipairs(versions) do
        if v == version then
            return true
        end
    end
    return false
end

-- Helper function to update or add to usage array
local function update_usage(usage_array, key, count)
    for i, item in ipairs(usage_array) do
        if item.version == key then
            item.client_count = item.client_count + count
            return
        end
    end
    table.insert(usage_array, {version = key, client_count = count})
end

-- Helper function to update or add to platform/arch/channel array
local function update_usage_array(usage_array, key, count)
    for i, item in ipairs(usage_array) do
        if item.platform == key then
            item.client_count = item.client_count + count
            return
        end
    end
    table.insert(usage_array, {platform = key, client_count = count})
end

-- Get all apps if app_name is '*'
local apps = {}
if app_name == "*" then
    -- Debug: Log the date range we're working with
    debug_log('debug:working_date_range', cjson.encode(date_range))
    
    -- Get all apps that have data for any date in the range
    local all_apps = {}
    for _, date in ipairs(date_range) do
        local pattern = "stats:" .. admin .. ":*:requests:" .. date
        local keys = redis.call('KEYS', pattern)
        for _, key in ipairs(keys) do
            local app = string.match(key, "stats:" .. admin .. ":([^:]+):")
            if app then
                all_apps[app] = true
            end
        end
    end
    
    -- Convert table to array
    for app, _ in pairs(all_apps) do
        table.insert(apps, app)
    end
else
    table.insert(apps, app_name)
end

-- Debug: Log found apps
debug_log('debug:found_apps', cjson.encode(apps))

-- First collect all known versions
local all_known_versions = {}
for _, app in ipairs(apps) do
    local known_versions_key = "stats:" .. admin .. ":" .. app .. ":known_versions"
    local known_versions = redis.call('SMEMBERS', known_versions_key)
    
    -- Debug: Log known versions for each app
    debug_log('debug:known_versions_' .. app, cjson.encode(known_versions))
    
    -- Debug: Log the key we're checking
    debug_log('debug:checking_key_' .. app, known_versions_key)
    
    -- Debug: Log the number of versions found
    debug_log('debug:versions_count_' .. app, #known_versions)
    
    for _, version in ipairs(known_versions) do
        if not version_exists(all_known_versions, version) then
            table.insert(all_known_versions, version)
        end
    end
end

-- Debug: Log all collected versions before sorting
debug_log('debug:all_versions_before_sort', cjson.encode(all_known_versions))

-- Sort versions and assign to result
table.sort(all_known_versions)
result.versions.known_versions = all_known_versions

-- Debug: Log collected known versions
debug_log('debug:collected_known_versions', cjson.encode(result.versions.known_versions))

-- Process each app
for _, app in ipairs(apps) do
    -- Debug: Log current app and date range
    debug_log('debug:processing_app_' .. app, cjson.encode({
        app = app,
        date_range = date_range
    }))
    
    -- Process each date in the range
    for _, date in ipairs(date_range) do
        local base_pattern = "stats:" .. admin .. ":" .. app
        
        -- Debug: Log current date processing
        debug_log('debug:processing_date_' .. app .. '_' .. date, cjson.encode({
            date = date,
            base_pattern = base_pattern
        }))
        
        -- Get total requests
        local requests_key = base_pattern .. ":requests:" .. date
        local requests = tonumber(redis.call('GET', requests_key)) or 0
        result.total_requests = result.total_requests + requests
        
        -- Get unique clients
        local clients_key = base_pattern .. ":unique_clients:" .. date
        local unique_count = redis.call('SCARD', clients_key)
        result.unique_clients = result.unique_clients + unique_count
        
        -- Get latest version clients
        local latest_key = base_pattern .. ":clients_using_latest_version:" .. date
        local latest_count = redis.call('SCARD', latest_key)
        result.clients_using_latest_version = result.clients_using_latest_version + latest_count
        
        -- Get outdated clients
        local outdated_key = base_pattern .. ":clients_outdated:" .. date
        local outdated_count = redis.call('SCARD', outdated_key)
        result.clients_outdated = result.clients_outdated + outdated_count

        -- Debug: Log daily stats before update
        debug_log('debug:daily_stats_before_' .. app .. '_' .. date, cjson.encode(result.daily_stats))

        -- Update daily stats
        local found_daily = false
        for _, daily in ipairs(result.daily_stats) do
            if daily.date == date then
                daily.total_requests = daily.total_requests + requests
                daily.unique_clients = daily.unique_clients + unique_count
                daily.clients_using_latest_version = daily.clients_using_latest_version + latest_count
                daily.clients_outdated = daily.clients_outdated + outdated_count
                found_daily = true
                break
            end
        end
        
        if not found_daily then
            local new_daily = {
                date = date,
                total_requests = requests,
                unique_clients = unique_count,
                clients_using_latest_version = latest_count,
                clients_outdated = outdated_count
            }
            table.insert(result.daily_stats, new_daily)
            -- Debug: Log new daily stats entry
            debug_log('debug:new_daily_stats_' .. app .. '_' .. date, cjson.encode(new_daily))
        end

        -- Debug: Log daily stats after update
        debug_log('debug:daily_stats_after_' .. app .. '_' .. date, cjson.encode(result.daily_stats))
        
        -- Debug: Log requests for this date
        debug_log('debug:requests_' .. app .. '_' .. date, tostring(requests))
        
        -- Debug: Log unique clients for this date
        debug_log('debug:unique_clients_' .. app .. '_' .. date, tostring(unique_count))
        
        -- Debug: Log latest version clients for this date
        debug_log('debug:latest_version_clients_' .. app .. '_' .. date, tostring(latest_count))
        
        -- Debug: Log outdated clients for this date
        debug_log('debug:outdated_clients_' .. app .. '_' .. date, tostring(outdated_count))
        
        -- Get version usage for all known versions
        for _, version in ipairs(result.versions.known_versions) do
            local version_key = base_pattern .. ":version_usage:" .. date .. ":" .. version
            local version_count = redis.call('SCARD', version_key)
            if version_count > 0 then
                update_usage(result.versions.usage, version, version_count)
                -- Debug: Log version usage for this date
                debug_log('debug:version_usage_' .. app .. '_' .. date .. '_' .. version, tostring(version_count))
            end
        end
        
        -- Get platform usage
        local platform_pattern = base_pattern .. ":platforms:" .. date .. ":*"
        local platform_keys = redis.call('KEYS', platform_pattern)
        for _, key in ipairs(platform_keys) do
            local platform = string.match(key, ":([^:]+)$")
            if in_array(filter_platforms, platform) then
                local platform_count = redis.call('SCARD', key)
                if platform_count > 0 then
                    update_usage_array(result.platforms, platform, platform_count)
                    -- Debug: Log platform usage for this date
                    debug_log('debug:platform_usage_' .. app .. '_' .. date .. '_' .. platform, tostring(platform_count))
                end
            end
        end
        
        -- Get architecture usage
        local arch_pattern = base_pattern .. ":architectures:" .. date .. ":*"
        local arch_keys = redis.call('KEYS', arch_pattern)
        for _, key in ipairs(arch_keys) do
            local arch = string.match(key, ":([^:]+)$")
            if in_array(filter_architectures, arch) then
                local arch_count = redis.call('SCARD', key)
                if arch_count > 0 then
                    update_usage_array(result.architectures, arch, arch_count)
                    -- Debug: Log architecture usage for this date
                    debug_log('debug:arch_usage_' .. app .. '_' .. date .. '_' .. arch, tostring(arch_count))
                end
            end
        end
        
        -- Get channel usage
        local channel_pattern = base_pattern .. ":channels:" .. date .. ":*"
        local channel_keys = redis.call('KEYS', channel_pattern)
        for _, key in ipairs(channel_keys) do
            local channel = string.match(key, ":([^:]+)$")
            if in_array(filter_channels, channel) then
                local channel_count = redis.call('SCARD', key)
                if channel_count > 0 then
                    update_usage_array(result.channels, channel, channel_count)
                    -- Debug: Log channel usage for this date
                    debug_log('debug:channel_usage_' .. app .. '_' .. date .. '_' .. channel, tostring(channel_count))
                end
            end
        end
    end
end

-- Sort daily stats by date
table.sort(result.daily_stats, function(a, b) return a.date < b.date end)

-- Debug: Log final daily stats
debug_log('debug:final_daily_stats', cjson.encode(result.daily_stats))

-- Debug: Log final known versions
debug_log('debug:final_known_versions', cjson.encode(result.versions.known_versions))

-- Calculate total active apps (count apps that have any data for the date range)
local active_apps = {}
for _, app in ipairs(apps) do
    local has_data = false
    for _, date in ipairs(date_range) do
        local base_pattern = "stats:" .. admin .. ":" .. app
        -- Check if app has any data for this date
        local requests = tonumber(redis.call('GET', base_pattern .. ":requests:" .. date)) or 0
        local unique_clients = redis.call('SCARD', base_pattern .. ":unique_clients:" .. date)
        if requests > 0 or unique_clients > 0 then
            has_data = true
            break
        end
    end
    if has_data then
        table.insert(active_apps, app)
    end
end

-- Debug: Log active apps before counting
debug_log('debug:active_apps_before_count', cjson.encode(active_apps))

-- Set total active apps
local active_apps_count = #active_apps
debug_log('debug:active_apps_count', tostring(active_apps_count))
result.total_active_apps = active_apps_count
debug_log('debug:result_total_active_apps', tostring(result.total_active_apps))

-- Debug: Log active apps
debug_log('debug:active_apps', cjson.encode(active_apps))

-- Calculate used versions count (count versions that have usage data)
local used_versions = {}
for _, usage in ipairs(result.versions.usage) do
    if usage.client_count > 0 then
        table.insert(used_versions, usage.version)
    end
end

-- Debug: Log used versions before counting
debug_log('debug:used_versions_before_count', cjson.encode(used_versions))

-- Set used versions count
local used_versions_count = #used_versions
debug_log('debug:used_versions_count', tostring(used_versions_count))
result.versions.used_versions_count = used_versions_count
debug_log('debug:result_used_versions_count', tostring(result.versions.used_versions_count))

-- Debug: Log used versions
debug_log('debug:used_versions', cjson.encode(used_versions))

-- Debug: Log version usage
debug_log('debug:version_usage', cjson.encode(result.versions.usage))

-- Ensure all arrays are properly initialized
if #result.versions.known_versions == 0 then
    result.versions.known_versions = {}
end
if #result.versions.usage == 0 then
    result.versions.usage = {}
end
if #result.platforms == 0 then
    result.platforms = {}
end
if #result.architectures == 0 then
    result.architectures = {}
end
if #result.channels == 0 then
    result.channels = {}
end

-- Debug: Log final result before encoding
debug_log('debug:final_result_before_encode', cjson.encode(result))

-- Debug: Log final result
debug_log('debug:final_result', cjson.encode(result))

return cjson.encode(result) 