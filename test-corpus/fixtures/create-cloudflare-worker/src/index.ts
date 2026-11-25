export default {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/hello") {
      return new Response("Hello from the worker");
    }
    return new Response("Not found", { status: 404 });
  },
};
