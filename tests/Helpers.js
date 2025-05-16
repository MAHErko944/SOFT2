const request = require('supertest');
const cheerio = require('cheerio');

const getCsrfToken = async (app, route = '/') => {
  const agent = request.agent(app);
  const response = await agent.get(route);
  const $ = cheerio.load(response.text);
  const csrfToken = $('input[name="_csrf"]').val() || 'test-token';
  return { agent, csrfToken };
};

const csrfRequest = (app) => {
  return {
    get: (url) => request(app).get(url).set('x-csrf-bypass', 'true'),
    post: (url) => request(app).post(url).set('x-csrf-bypass', 'true'),
    put: (url) => request(app).put(url).set('x-csrf-bypass', 'true'),
    patch: (url) => request(app).patch(url).set('x-csrf-bypass', 'true'),
    delete: (url) => request(app).delete(url).set('x-csrf-bypass', 'true')
  };
};

const extendAgentWithCsrf = (agent) => {
  const originalGet = agent.get;
  const originalPost = agent.post;
  const originalPut = agent.put;
  const originalPatch = agent.patch;
  const originalDelete = agent.delete;
  
  agent.get = function(url) { return originalGet.call(this, url).set('x-csrf-bypass', 'true'); };
  agent.post = function(url) { return originalPost.call(this, url).set('x-csrf-bypass', 'true'); };
  agent.put = function(url) { return originalPut.call(this, url).set('x-csrf-bypass', 'true'); };
  agent.patch = function(url) { return originalPatch.call(this, url).set('x-csrf-bypass', 'true'); };
  agent.delete = function(url) { return originalDelete.call(this, url).set('x-csrf-bypass', 'true'); };
  
  return agent;
};

const createCsrfAgent = (app) => {
  const agent = request.agent(app);
  return extendAgentWithCsrf(agent);
};

module.exports = {
  getCsrfToken,
  csrfRequest,
  extendAgentWithCsrf,
  createCsrfAgent
};