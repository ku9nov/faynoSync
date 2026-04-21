local current = redis.call("GET", KEYS[1])

if ARGV[1] ~= "" then
	if current == ARGV[1] then
		redis.call("SET", KEYS[1], ARGV[2])
		return 1
	end
	return 0
end

if not current then
	redis.call("SET", KEYS[1], ARGV[2])
	return 1
end

return 0
