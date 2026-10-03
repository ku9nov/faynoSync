# FaynoSync Dashboard


![demo](https://github.com/user-attachments/assets/17ab8692-d445-44bf-8a30-dc164025f805)



### 🧠 This frontend is the result of vibe coding

The entire UI was built with the help of AI coding assistants — that's what made this possible, since I'm a **DevOps engineer**, not a frontend developer 😅

I did my best, but if you see anything that can be improved — **any suggestions, feedback, or corrections are more than welcome!** 🙌


## Description 📄

The admin dashboard of [faynoSync](../README.md). The API binary embeds its production build and serves it at `/dashboard/`.

## Development

Start the API on `http://localhost:9000`, then:

```
yarn install
yarn dev
```

The dev server runs on `http://localhost:3000/dashboard/` and proxies every request outside `/dashboard/` to the API, so no configuration is needed.

## Building

Build before `go build` to embed the dashboard into the binary (the output goes to `../server/dashboard/ui/dist`):

```
yarn build
```
