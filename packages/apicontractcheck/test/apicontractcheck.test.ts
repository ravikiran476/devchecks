import { describe, expect, it } from 'vitest';
import { createValidatingFetch, diffSpecs, fromHar, loadSpec, matchOperation, validateExchange, validateSchema, type OpenAPISpec } from '../src/index.js';

const specYaml = `
openapi: 3.0.3
info: { title: Shop, version: 1.0.0 }
servers: [{ url: https://api.shop.test/v1 }]
paths:
  /users/me:
    get:
      operationId: me
      responses:
        '200': { $ref: '#/components/responses/User' }
  /users/{id}:
    parameters:
      - { name: id, in: path, required: true, schema: { type: integer }, example: 1 }
    get:
      operationId: getUser
      parameters:
        - { name: expand, in: query, schema: { type: string, enum: [orders] } }
      responses:
        '200': { $ref: '#/components/responses/User' }
        '404':
          description: Not found
          content:
            application/problem+json:
              schema: { $ref: '#/components/schemas/Problem' }
  /orders:
    post:
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [items]
              properties:
                items: { type: array, minItems: 1, items: { type: string } }
                coupon: { type: string, maxLength: 20 }
      responses:
        '201':
          description: Created
          headers:
            Location: { required: true, schema: { type: string } }
components:
  responses:
    User:
      description: A user
      content:
        application/json:
          schema: { $ref: '#/components/schemas/User' }
  schemas:
    User:
      type: object
      required: [id, email, role]
      additionalProperties: false
      properties:
        id: { type: integer, readOnly: true }
        email: { type: string, format: email }
        role: { type: string, enum: [admin, member] }
        nickname: { type: string, nullable: true }
        password: { type: string, writeOnly: true }
        pet:
          oneOf: [{ $ref: '#/components/schemas/Cat' }, { $ref: '#/components/schemas/Dog' }]
          discriminator: { propertyName: kind }
    Cat: { type: object, required: [kind, lives], properties: { kind: { type: string }, lives: { type: integer, maximum: 9 } } }
    Dog: { type: object, required: [kind, breed], properties: { kind: { type: string }, breed: { type: string } } }
    Problem: { type: object, required: [title], properties: { title: { type: string } } }
`;
const spec = loadSpec(specYaml);
const user = { id: 1, email: 'a@b.co', role: 'admin', nickname: null };

describe('spec matching', () => {
  it('strips server base paths and prefers literal paths', () => {
    expect(matchOperation(spec, 'GET', 'https://api.shop.test/v1/users/me').match?.template).toBe('/users/me');
    const m = matchOperation(spec, 'get', '/v1/users/42?expand=orders').match!;
    expect(m.template).toBe('/users/{id}');
    expect(m.pathParams).toEqual({ id: '42' });
    expect(m.parameters.map((p) => p.name)).toEqual(['id', 'expand']);
  });

  it('rejects Swagger 2.0 with a hint', () => {
    expect(() => loadSpec({ swagger: '2.0' })).toThrow(/swagger2openapi/);
  });
});

describe('schema validation', () => {
  const ctx = { spec, direction: 'response' as const };
  it('validates types, formats, enums, nullable and additionalProperties', () => {
    expect(validateSchema({ $ref: '#/components/schemas/User' }, user, ctx)).toEqual([]);
    const errors = validateSchema({ $ref: '#/components/schemas/User' }, { id: '1', email: 'nope', role: 'owner', extra: 1, password: 'x' }, ctx);
    expect(errors.map((e) => [e.path, e.keyword])).toEqual([
      ['/id', 'type'],
      ['/email', 'format'],
      ['/role', 'enum'],
      ['/extra', 'additionalProperties'],
      ['/password', 'writeOnly'],
    ]);
  });

  it('uses the discriminator to report errors in the right branch', () => {
    const errors = validateSchema({ $ref: '#/components/schemas/User' }, { ...user, pet: { kind: 'Cat', lives: 12 } }, ctx);
    expect(errors).toEqual([{ path: '/pet/lives', keyword: 'maximum', message: 'must be <= 9' }]);
  });

  it('skips readOnly required properties in requests', () => {
    expect(validateSchema({ $ref: '#/components/schemas/User' }, { email: 'a@b.co', role: 'member', password: 'secret' }, { spec, direction: 'request' })).toEqual([]);
  });

  it('supports OpenAPI 3.1 type arrays', () => {
    const s31 = loadSpec({ openapi: '3.1.0', paths: {} });
    expect(validateSchema({ type: ['string', 'null'] }, null, { spec: s31, direction: 'response' })).toEqual([]);
    expect(validateSchema({ type: 'number', exclusiveMinimum: 0 }, 0, { spec: s31, direction: 'response' })[0]?.keyword).toBe('exclusiveMinimum');
  });
});

describe('validateExchange', () => {
  const rules = (fs: Array<{ ruleId: string }>) => fs.map((f) => f.ruleId);

  it('accepts a valid response and reports schema violations with pointers', () => {
    expect(validateExchange(spec, { method: 'GET', url: '/v1/users/1', status: 200, headers: { 'content-type': 'application/json' }, body: JSON.stringify(user) })).toEqual([]);
    const [f] = validateExchange(spec, { method: 'GET', url: '/v1/users/1', status: 200, headers: { 'content-type': 'application/json; charset=utf-8' }, body: { ...user, role: 'owner' } });
    expect(f).toMatchObject({ ruleId: 'response-schema-violation', severity: 'high', message: 'GET /users/{id} 200: /role must be one of "admin", "member".' });
  });

  it('reports undocumented paths, methods, statuses and media types', () => {
    expect(rules(validateExchange(spec, { method: 'GET', url: '/v1/nope', status: 200 }))).toEqual(['undocumented-path']);
    expect(rules(validateExchange(spec, { method: 'DELETE', url: '/v1/users/1', status: 204 }))).toEqual(['undocumented-method']);
    expect(validateExchange(spec, { method: 'GET', url: '/v1/users/1', status: 500, body: 'oops' })[0]).toMatchObject({ ruleId: 'undocumented-status', severity: 'high' });
    expect(rules(validateExchange(spec, { method: 'GET', url: '/v1/users/1', status: 200, headers: { 'content-type': 'text/html' }, body: '<html>' }))).toEqual(['undocumented-content-type']);
    expect(validateExchange(spec, { method: 'GET', url: '/v1/users/9', status: 404, headers: { 'content-type': 'application/problem+json' }, body: '{"title":"Not found"}' })).toEqual([]);
  });

  it('optionally validates requests and checks required response headers', () => {
    const findings = validateExchange(
      spec,
      { method: 'POST', url: '/v1/orders', request: { headers: { 'content-type': 'application/json' }, body: '{"items":[],"coupon":"x"}' }, status: 201, headers: {} },
      { requests: true },
    );
    expect(findings.map((f) => [f.ruleId, f.message])).toEqual([
      ['request-schema-violation', 'POST /orders: request body /items must have at least 1 items.'],
      ['missing-response-header', 'POST /orders 201 is missing the required header Location.'],
    ]);
    expect(rules(validateExchange(spec, { method: 'GET', url: '/v1/users/1?expand=all', status: 200, headers: { 'content-type': 'application/json' }, body: user }, { requests: true }))).toEqual(['request-schema-violation']);
  });
});

describe('HAR and fetch integration', () => {
  it('reads API calls from a HAR file', () => {
    const har = {
      log: {
        entries: [
          { request: { method: 'GET', url: 'https://api.shop.test/v1/users/me' }, response: { status: 200, headers: [{ name: 'Content-Type', value: 'application/json' }], content: { mimeType: 'application/json', text: JSON.stringify(user) } } },
          { request: { method: 'GET', url: 'https://api.shop.test/logo.png' }, response: { status: 200, content: { mimeType: 'image/png' } } },
        ],
      },
    };
    const ex = fromHar(har);
    expect(ex).toHaveLength(1);
    expect(validateExchange(spec, ex[0]!)).toEqual([]);
  });

  it('wraps fetch and reports contract violations without changing the response', async () => {
    const seen: string[] = [];
    const fakeFetch = (async () => new Response(JSON.stringify({ ...user, email: 'bad' }), { status: 200, headers: { 'content-type': 'application/json' } })) as typeof fetch;
    const f = createValidatingFetch(spec, { fetch: fakeFetch, onFinding: (x) => seen.push(x.message) });
    const res = await f('https://api.shop.test/v1/users/me');
    expect((await res.json()).email).toBe('bad');
    expect(seen).toEqual(['GET /users/me 200: /email must be a valid email.']);
  });
});

describe('diffSpecs', () => {
  it('detects breaking request and response changes', () => {
    const next = structuredClone(spec) as OpenAPISpec & { paths: Record<string, Record<string, any>>; components: any };
    delete next.paths['/users/me'];
    next.paths['/users/{userId}'] = next.paths['/users/{id}']!; // renamed path param: not breaking
    delete next.paths['/users/{id}'];
    next.paths['/users/{userId}'].parameters[0].name = 'userId';
    next.paths['/users/{userId}'].get.parameters.push({ name: 'tenant', in: 'query', required: true, schema: { type: 'string' } });
    next.paths['/orders']!.post.requestBody.content['application/json'].schema.required.push('address');
    next.paths['/orders']!.post.requestBody.content['application/json'].schema.properties.coupon.maxLength = 10;
    next.components.schemas.User.properties.role.enum.push('guest');
    delete next.components.schemas.User.properties.nickname;
    next.paths['/health'] = { get: { responses: { '200': { description: 'ok' } } } };

    const { breaking, nonBreaking } = diffSpecs(spec, next);
    expect(breaking.map((f) => [f.ruleId, f.severity])).toEqual([
      ['endpoint-removed', 'high'],
      ['required-parameter-added', 'high'],
      ['property-removed', 'high'],
      ['enum-widened', 'medium'],
      ['required-property-added', 'high'],
      ['constraint-tightened', 'medium'],
    ]);
    expect(nonBreaking.map((f) => f.ruleId)).toEqual(['endpoint-added']);
  });
});
