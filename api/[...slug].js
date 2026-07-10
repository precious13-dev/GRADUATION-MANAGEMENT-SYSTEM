const BACKEND = 'https://graduation-management-system.onrender.com';

module.exports = async (req, res) => {
  const { slug } = req.query;
  const apiPath = (slug || []).join('/');
  const targetUrl = `${BACKEND}/api/${apiPath}`;

  const url = new URL(targetUrl);
  const origUrl = new URL(req.url, 'http://localhost');
  url.search = origUrl.search;

  const headers = {};
  for (const [key, value] of Object.entries(req.headers)) {
    if (key === 'host' || key === 'connection') continue;
    headers[key] = value;
  }

  const init = { method: req.method, headers };

  if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    init.body = Buffer.concat(chunks);
  }

  try {
    const resp = await fetch(url.toString(), init);
    const respHeaders = {};
    resp.headers.forEach((v, k) => {
      if (k === 'transfer-encoding') return;
      respHeaders[k] = v;
    });
    res.writeHead(resp.status, respHeaders);
    const body = await resp.arrayBuffer();
    res.end(Buffer.from(body));
  } catch (e) {
    res.writeHead(502, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ success: false, message: 'Backend unreachable: ' + e.message }));
  }
};

module.exports.config = { runtime: 'nodejs18.x' };
