# Nginx Configuration for faynoSync

If you're deploying `faynoSync` behind an Nginx reverse proxy, here's a sample configuration optimized for caching and performance.

## Overview

This configuration provides:
- Reverse proxy setup for the faynoSync backend API
- Optimized caching for the `/checkVersion` endpoint
- WebSocket support for real-time features
- Rate limiting capabilities (optional)
- Proper header forwarding and SSL termination support

## Quick Setup

1. Copy the configuration file to your Nginx sites directory:
   ```bash
   sudo cp faynosync.conf /etc/nginx/sites-available/faynosync.conf
   ```

2. Enable the site:
   ```bash
   sudo ln -s /etc/nginx/sites-available/faynosync.conf /etc/nginx/sites-enabled/
   ```

3. Test the configuration:
   ```bash
   sudo nginx -t
   ```

4. Reload Nginx:
   ```bash
   sudo systemctl reload nginx
   ```

## Configuration Details

### Global Settings (Add to main nginx.conf)

Add these lines to the `http` block in your main `nginx.conf`:

```nginx
# Enable caching for the /checkVersion endpoint
proxy_cache_path /tmp/nginx_cache levels=1:2 keys_zone=checkversion_cache:10m inactive=60s max_size=100m;

# Optional: enable rate limiting
limit_req_zone $binary_remote_addr zone=req_limit:10m rate=10r/s;
```

### Server Block Configuration

The main server block includes:

- **Port 80**: Standard HTTP port (consider adding SSL/HTTPS)
- **Server Name**: `faynosync.example.com` (update to your domain)
- **Log Files**: Separate access and error logs for easy debugging
- **Client Max Body Size**: 1000M for large file uploads

### Location Blocks

#### Default Location (`/`)
Handles all general API requests with:
- WebSocket upgrade support (for future WebSocket features)
- Proper header forwarding
- Reasonable timeout settings

#### Optimized `/checkVersion` Location
Specialized configuration for version checking with:
- **Microcaching**: 60-second cache duration
- **Stale Cache**: Serves cached content if backend is slow
- **Cache Locking**: Prevents multiple upstream requests
- **Cache Status Header**: `X-Cache-Status` for monitoring

## Performance Optimizations

### Caching Strategy
- **Cache Duration**: 60 seconds for version checks
- **Cache Size**: 100MB maximum with 10MB memory zone
- **Stale Content**: Serves cached content during backend issues
- **Background Updates**: Updates cache in background

### Rate Limiting (Optional)
Uncomment the rate limiting lines to enable:
- **Zone**: 10MB memory for storing client IPs
- **Rate**: 10 requests per second per IP
- **Burst**: 20 requests allowed in burst

## Security Considerations

### Headers
The configuration properly forwards security headers:
- `X-Real-IP`: Client's real IP address
- `X-Forwarded-For`: Original client IP in proxy chain
- `X-Forwarded-Proto`: Original protocol (http/https)

## SSL/HTTPS Setup

For production, add SSL configuration:

```nginx
server {
    listen 443 ssl http2;
    server_name faynosync.example.com;
    
    ssl_certificate /path/to/your/certificate.crt;
    ssl_certificate_key /path/to/your/private.key;
    
    # SSL configuration...
    
    # Include the rest of the configuration...
}
```

## Monitoring and Debugging

### Cache Status
Check cache effectiveness via the `X-Cache-Status` header:
- `HIT`: Request served from cache
- `MISS`: Request fetched from backend
- `UPDATING`: Cache is being updated in background
- `STALE`: Served stale content due to backend issues

### Log Files
Monitor these log files for issues:
- `/var/log/nginx/faynosync.access.log`
- `/var/log/nginx/faynosync.error.log`

### Cache Statistics
View cache statistics in Nginx status page (if enabled):
```nginx
location /nginx_status {
    stub_status on;
    access_log off;
    allow 127.0.0.1;
    deny all;
}
```

## Troubleshooting

### Common Issues

1. **Cache Not Working**
   - Check if cache directory exists and is writable
   - Verify cache zone is defined in main nginx.conf
   - Check `X-Cache-Status` header in responses

2. **WebSocket Issues**
   - Ensure `Upgrade` and `Connection` headers are set
   - Check if backend supports WebSocket upgrades
   - Verify `proxy_cache_bypass` is configured
   - Note: WebSocket support is pre-configured for future use, but not currently implemented in the backend

3. **Large File Uploads**
   - Increase `client_max_body_size` if needed
   - Check backend timeout settings
   - Monitor disk space for uploads

### Performance Tuning

1. **Adjust Cache Settings**
   - Increase cache size for higher traffic
   - Modify cache duration based on update frequency
   - Tune cache memory usage

2. **Rate Limiting**
   - Adjust rate limits based on expected traffic
   - Monitor rate limit rejections in logs
   - Consider different limits for different endpoints

## Notes

- The `/checkVersion` endpoint is safely cacheable for short periods (e.g. 60 seconds) due to its idempotent nature
- You can enable rate limiting by uncommenting the `limit_req` line
- Monitor cache hit rates to optimize cache duration settings 