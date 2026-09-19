var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// src_index.js
var CONFIG = {
  FIREBASE_PROJECT_ID: "lt-coaching",
  JWKS_URL: "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com",
  JWKS_CACHE_DURATION: 6 * 60 * 60 * 1e3,
  ACCESS_DURATION_MONTHS: 9,
  MAX_DOCUMENTS: 50,
  MAX_FILE_SIZE: 100 * 1024 * 1024,
  PDF_MIME_TYPE: "application/pdf"
};

// Endpoints Orange Money WebPayment API
var ORANGE_OAUTH_API = "https://api.orange.com/oauth/v3/token";
var ORANGE_WEBPAY_API = "https://api.orange.com/orange-money-webpay/dev/v1/webpayment";
var ORANGE_STATUS_API = "https://api.orange.com/orange-money-webpay/dev/v1/transactionstatus";

var ALLOWED_ORIGINS = [
  "https://ika-book.com",
  "https://www.ika-book.com",
  "https://lt-coaching-biblio.pages.dev"
];

var cachedJwks = null;
var cachedJwksTime = 0;
var encoder = new TextEncoder();
var decoder = new TextDecoder();

function getCorsHeaders(request) {
  const origin = request?.headers?.get("Origin") || "";
  const allowedOrigin = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[1];
  return {
    "Access-Control-Allow-Origin": allowedOrigin,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, x-server-key",
    "Access-Control-Max-Age": "86400"
  };
}
__name(getCorsHeaders, "getCorsHeaders");

function handleOptions(request) {
  return new Response(null, {
    status: 204,
    headers: getCorsHeaders(request)
  });
}
__name(handleOptions, "handleOptions");

function json(request, data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...getCorsHeaders(request),
      "Content-Type": "application/json"
    }
  });
}
__name(json, "json");

function success(request, data = {}) {
  return json(request, data, 200);
}
__name(success, "success");

function created(request, data = {}) {
  return json(request, data, 201);
}
__name(created, "created");

function badRequest(request, message) {
  return json(request, { success: false, error: message }, 400);
}
__name(badRequest, "badRequest");

function forbidden(request, message) {
  return json(request, { success: false, error: message }, 403);
}
__name(forbidden, "forbidden");

function notFound(request, message) {
  return json(request, { success: false, error: message }, 404);
}
__name(notFound, "notFound");

function serverError(request, error) {
  console.error(error);
  return json(request, { success: false, error: error.message }, 500);
}
__name(serverError, "serverError");

function base64UrlDecode(str) {
  let padded = str.replace(/-/g, "+").replace(/_/g, "/");
  while (padded.length % 4) {
    padded += "=";
  }
  return atob(padded);
}
__name(base64UrlDecode, "base64UrlDecode");

function toBase64(bytes) {
  return btoa(String.fromCharCode(...bytes));
}
__name(toBase64, "toBase64");

function fromBase64(base64) {
  return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
}
__name(fromBase64, "fromBase64");

function generateDocumentId() {
  return `doc_${Date.now()}_${crypto.randomUUID()}`;
}
__name(generateDocumentId, "generateDocumentId");

function generateFileName(documentId) {
  return `${documentId}.pdf`;
}
__name(generateFileName, "generateFileName");

function addMonths(months) {
  const date = new Date();
  date.setMonth(date.getMonth() + months);
  return date.toISOString();
}
__name(addMonths, "addMonths");

function isPdf(file) {
  return file.type === CONFIG.PDF_MIME_TYPE;
}
__name(isPdf, "isPdf");

function isValidFileSize(file) {
  return file.size <= CONFIG.MAX_FILE_SIZE;
}
__name(isValidFileSize, "isValidFileSize");

async function getMasterKey(secretKey) {
  const hash = await crypto.subtle.digest("SHA-256", encoder.encode(secretKey));
  return crypto.subtle.importKey(
    "raw",
    hash,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  );
}
__name(getMasterKey, "getMasterKey");

async function encryptDocumentKey(documentKey, secretKey) {
  const masterKey = await getMasterKey(secretKey);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    masterKey,
    encoder.encode(documentKey)
  );
  const combined = new Uint8Array(iv.length + encrypted.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(encrypted), iv.length);
  return toBase64(combined);
}
__name(encryptDocumentKey, "encryptDocumentKey");

async function decryptDocumentKey(encryptedKey, secretKey) {
  const masterKey = await getMasterKey(secretKey);
  const combined = fromBase64(encryptedKey);
  const iv = combined.slice(0, 12);
  const data = combined.slice(12);
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    masterKey,
    data
  );
  return decoder.decode(decrypted);
}
__name(decryptDocumentKey, "decryptDocumentKey");

async function getJwks() {
  const now = Date.now();
  if (!cachedJwks || now - cachedJwksTime > CONFIG.JWKS_CACHE_DURATION) {
    const response = await fetch(CONFIG.JWKS_URL);
    if (!response.ok) {
      throw new Error("Impossible de récupérer les clés Firebase.");
    }
    cachedJwks = await response.json();
    cachedJwksTime = now;
  }
  return cachedJwks;
}
__name(getJwks, "getJwks");

async function verifyFirebaseToken(request) {
  const authorization = request.headers.get("Authorization");
  
  if (!authorization) {
    throw new Error("Token d'authentification manquant ou mal formaté.");
  }
  if (!authorization.startsWith("Bearer ")) {
    throw new Error("Format du token invalide. Le préfixe 'Bearer ' est requis.");
  }
  
  const token = authorization.substring(7).trim(); 
  
  if (!token || token === "null" || token === "undefined") {
    throw new Error("Token d'authentification vide ou indéfini.");
  }

  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("JWT invalide ou mal formaté.");
  }

  const header = JSON.parse(base64UrlDecode(parts[0]));
  const payload = JSON.parse(base64UrlDecode(parts[1]));
  const now = Math.floor(Date.now() / 1000);
  
  if (payload.exp < now) {
    throw new Error("Token expiré.");
  }
  if (payload.aud !== CONFIG.FIREBASE_PROJECT_ID) {
    throw new Error("Audience invalide.");
  }
  if (payload.iss !== `https://securetoken.google.com/${CONFIG.FIREBASE_PROJECT_ID}`) {
    throw new Error("Émetteur invalide.");
  }

  const jwks = await getJwks();
  const jwk = jwks.keys.find((key) => key.kid === header.kid);
  if (!jwk) {
    throw new Error("Clé publique introuvable.");
  }

  const publicKey = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );

  const valid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    publicKey,
    Uint8Array.from(base64UrlDecode(parts[2]), (c) => c.charCodeAt(0)),
    encoder.encode(`${parts[0]}.${parts[1]}`)
  );

  if (!valid) {
    throw new Error("Signature invalide.");
  }

  return {
    uid: payload.user_id || payload.sub,
    email: payload.email,
    payload
  };
}
__name(verifyFirebaseToken, "verifyFirebaseToken");

// ====================================================================
// UTILITAIRE ORANGE MONEY
// ====================================================================
async function getOrangeAccessToken(env) {
  if (!env.ORANGE_AUTH_HEADER) {
    throw new Error("Variable d'environnement ORANGE_AUTH_HEADER manquante.");
  }

  const tokenResponse = await fetch(ORANGE_OAUTH_API, {
    method: "POST",
    headers: {
      "Authorization": `Basic ${env.ORANGE_AUTH_HEADER}`,
      "Content-Type": "application/x-www-form-urlencoded",
      "Accept": "application/json"
    },
    body: "grant_type=client_credentials"
  });

  const responseText = await tokenResponse.text();
  let tokenData;
  try {
    tokenData = JSON.parse(responseText);
  } catch (e) {
    throw new Error(`Orange API a renvoyé un format non-JSON : ${responseText}`);
  }

  if (!tokenData.access_token) {
    throw new Error(`Échec d'obtention du jeton Orange Money: ${responseText}`);
  }

  return tokenData.access_token;
}
__name(getOrangeAccessToken, "getOrangeAccessToken");

async function getDocuments(env) {
  const { results } = await env.DB.prepare(
    `SELECT
      id, title, author, type, price, brutPrice, fileName, dateCreation
    FROM documents
    ORDER BY dateCreation DESC
    LIMIT ?`
  ).bind(CONFIG.MAX_DOCUMENTS).all();
  return results;
}
__name(getDocuments, "getDocuments");

async function getDocument(env, documentId) {
  return await env.DB.prepare(
    `SELECT * FROM documents WHERE id = ?`
  ).bind(documentId).first();
}
__name(getDocument, "getDocument");

async function saveDocument(env, document) {
  await env.DB.prepare(
    `INSERT INTO documents (
      id, title, author, type, price, brutPrice, fileName, 
      secretAuthorPhone, secretMobileMoneyOperator, dateCreation, encryptedKey, userId
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    document.id, document.title, document.author, document.type, 
    document.price, document.brutPrice, document.fileName, 
    document.phone, document.operator, document.dateCreation, document.encryptedKey, document.userId
  ).run();
}
__name(saveDocument, "saveDocument");

async function getDocumentsHandler(request, env) {
  try {
    const docs = await getDocuments(env);
    const origin = new URL(request.url).origin;
    const response = docs.map((doc) => ({
      ...doc,
      downloadUrl: `${origin}/api/download/${doc.fileName}`
    }));
    return success(request, response);
  } catch (error) {
    return serverError(request, error);
  }
}
__name(getDocumentsHandler, "getDocumentsHandler");

async function uploadHandler(request, env) {
  try {
    const user = await verifyFirebaseToken(request);
    const formData = await request.formData();
    const file = formData.get("file");
    
    if (!file) return badRequest(request, "Fichier manquant.");
    if (!isPdf(file)) return badRequest(request, "Seuls les PDF sont autorisés.");
    if (!isValidFileSize(file)) return badRequest(request, "Le fichier est trop volumineux.");
    const documentKey = formData.get("documentKey");
    if (!documentKey) return badRequest(request, "Clé du document manquante.");

    const documentId = generateDocumentId();
    const fileName = generateFileName(documentId);
    
    await env.MON_BUCKET.put(fileName, await file.arrayBuffer(), {
      httpMetadata: { contentType: file.type }
    });
    
    const encryptedKey = await encryptDocumentKey(documentKey, env.APP_SECRET_KEY);
    
    await saveDocument(env, {
      id: documentId,
      title: formData.get("title"),
      author: formData.get("author"),
      type: formData.get("type"),
      price: formData.get("price"),
      brutPrice: formData.get("brutPrice"),
      phone: formData.get("phone"),
      operator: formData.get("operator"),
      fileName,
      encryptedKey,
      dateCreation: (new Date()).toISOString(),
      userId: user.uid 
    });
    
    return created(request, { success: true, id: documentId });
  } catch (error) {
    return serverError(request, error);
  }
}
__name(uploadHandler, "uploadHandler");

async function downloadHandler(request, env, fileName) {
  try {
    if (!fileName || !fileName.endsWith(".pdf")) return badRequest(request, "Nom de fichier invalide.");
    const object = await env.MON_BUCKET.get(fileName);
    if (!object) return notFound(request, "Document introuvable.");
    const headers = new Headers(getCorsHeaders(request));
    object.writeHttpMetadata(headers);
    headers.set("Content-Type", object.httpMetadata?.contentType || "application/pdf");
    headers.set("Cache-Control", "public,max-age=86400");
    headers.set("Accept-Ranges", "bytes");
    return new Response(object.body, { status: 200, headers });
  } catch (error) {
    return serverError(request, error);
  }
}
__name(downloadHandler, "downloadHandler");

async function getPanierHandler(request, env) {
  try {
    const user = await verifyFirebaseToken(request);
    const result = await env.DB.prepare(
      `SELECT achats FROM paniers WHERE userId = ?`
    ).bind(user.uid).first();
    const achats = result?.achats ? JSON.parse(result.achats) : {};
    return success(request, { achats });
  } catch (error) {
    return serverError(request, error);
  }
}
__name(getPanierHandler, "getPanierHandler");

async function savePanierHandler(request, env) {
  try {
    const user = await verifyFirebaseToken(request);
    const body = await request.json();
    if (!body || typeof body !== "object") return badRequest(request, "Données invalides.");
    if (typeof body.achats !== "object") return badRequest(request, "Panier invalide.");
    await env.DB.prepare(
      `INSERT INTO paniers (userId, achats) VALUES (?, ?)
       ON CONFLICT(userId) DO UPDATE SET achats = excluded.achats`
    ).bind(user.uid, JSON.stringify(body.achats)).run();
    return success(request, { success: true, message: "Panier mis à jour" });
  } catch (error) {
    return serverError(request, error);
  }
}
__name(savePanierHandler, "savePanierHandler");

async function grantAccessHandler(request, env) {
  try {
    const body = await request.json();
    const docId = body.docId;
    let userId;
    const serverKey = request.headers.get("x-server-key");
    if (serverKey && serverKey === env.S2S_SECRET_KEY) {
      if (!body.userId) return badRequest(request, "userId manquant.");
      userId = body.userId;
    } else {
      const user = await verifyFirebaseToken(request);
      userId = user.uid;
    }
    if (!docId) return badRequest(request, "docId manquant.");
    const result = await env.DB.prepare(
      `SELECT achats FROM paniers WHERE userId = ?`
    ).bind(userId).first();
    const achats = result?.achats ? JSON.parse(result.achats) : {};
    achats[docId] = {
      purchaseDate: (new Date()).toISOString(),
      expiresAt: addMonths(CONFIG.ACCESS_DURATION_MONTHS),
      paymentMethod: serverKey ? "server" : "firebase"
    };
    await env.DB.prepare(
      `INSERT INTO paniers (userId, achats) VALUES (?, ?)
       ON CONFLICT(userId) DO UPDATE SET achats = excluded.achats`
    ).bind(userId, JSON.stringify(achats)).run();
    return success(request, { success: true, expiresAt: achats[docId].expiresAt });
  } catch (error) {
    return serverError(request, error);
  }
}
__name(grantAccessHandler, "grantAccessHandler");

// ====================================================================
// NOUVELLE LOGIQUE ORANGE MONEY : POST /api/pay-and-distribute
// ====================================================================
async function initiatePdfPaymentHandler(request, env) {
  try {
    if (!env.ORANGE_MERCHANT_KEY) {
      return serverError(request, new Error("ORANGE_MERCHANT_KEY manquante dans la configuration."));
    }

    const user = await verifyFirebaseToken(request);
    if (!user || !user.uid) {
      return badRequest(request, "Utilisateur non authentifié.");
    }
    
    let body;
    try {
      body = await request.json();
    } catch (e) {
      return badRequest(request, "Format de requête invalide (JSON attendu).");
    }
    
    const docId = body.docId;
    if (!docId) return badRequest(request, "docId manquant.");

    const doc = await getDocument(env, docId); 
    if (!doc) return notFound(request, "Document introuvable.");
    if (doc.type !== "payant") return badRequest(request, "Ce document n'est pas payant.");

    const rawPrice = doc.brutPrice || doc.price;
    if (!rawPrice) return badRequest(request, "Prix non défini dans la base de données.");

    const cleanPriceString = String(rawPrice).replace(/[^0-9]/g, '');
    const price = Number(cleanPriceString);

    if (isNaN(price) || price <= 0) return badRequest(request, "Prix du document invalide.");

    const accessToken = await getOrangeAccessToken(env);
    const order_id = `PDF_${Date.now()}_${Math.floor(Math.random() * 10000)}`;
    const url = new URL(request.url);

    // Requête vers l'API Orange Money WebPayment
    const payResponse = await fetch(ORANGE_WEBPAY_API, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${accessToken}`,
        "Accept": "application/json",
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        merchant_key: env.ORANGE_MERCHANT_KEY,
        currency: "OUV",
        order_id: order_id,
        amount: price,
        return_url: "https://www.ika-book.com/bibliotheque.html",
        cancel_url: "https://www.ika-book.com/bibliotheque.html",
        notif_url: `${url.origin}/s2s/pdf`,
        lang: "fr",
        reference: "Ika-Book PDF"
      })
    });

    const data = await payResponse.json();

    if (data.status === 201 || data.message === "OK") {
      const rawMetadata = JSON.stringify({
        userId: String(user.uid),
        docId: String(docId),
        pay_token: data.pay_token,
        notif_token: data.notif_token,
        amount: price,
        type: "pdf"
      });

      // Enregistrement initial de la commande en attente dans la table payments
      await env.DB.prepare(
        "INSERT OR REPLACE INTO payments (token, status, invoice_url, raw_data) VALUES (?, ?, ?, ?)"
      ).bind(order_id, "pending", data.payment_url || "", rawMetadata).run();

      return success(request, {
        success: true,
        message: "Facture Orange Money générée avec succès.",
        invoice_url: data.payment_url,
        token: order_id,
        pay_token: data.pay_token
      });
    } else {
      console.error("Erreur réponse Orange Money:", data);
      return badRequest(request, "Échec de création du paiement Orange Money.");
    }

  } catch (error) {
    console.error("Erreur initiatePdfPaymentHandler:", error);
    return serverError(request, error);
  }
}
__name(initiatePdfPaymentHandler, "initiatePdfPaymentHandler");

// ====================================================================
// NOUVELLE LOGIQUE ORANGE MONEY : WEBHOOK POST /s2s/pdf
// ====================================================================
async function s2sPdfWebhookHandler(request, env) {
  try {
    const rawBodyText = await request.text();
    let body;
    try {
      body = JSON.parse(rawBodyText);
    } catch (e) {
      return json(request, { error: "Payload JSON invalide" }, 400);
    }

    const { status, notif_token, txnid } = body;

    if (!notif_token) {
      return json(request, { error: "notif_token manquant" }, 400);
    }

    // Recherche du paiement via le notif_token stocké dans les métadonnées
    const { results } = await env.DB.prepare(
      "SELECT * FROM payments WHERE json_extract(raw_data, '$.notif_token') = ?"
    ).bind(notif_token).all();

    if (!results || results.length === 0) {
      return json(request, { error: "Paiement non trouvé" }, 404);
    }

    const payment = results[0];
    const rawParsed = JSON.parse(payment.raw_data);

    if (payment.status !== 'completed' && status === "SUCCESS") {
      const accessToken = await getOrangeAccessToken(env);

      // Vérification côté serveur auprès d'Orange Money
      const statusResponse = await fetch(ORANGE_STATUS_API, {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${accessToken}`,
          "Accept": "application/json",
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          order_id: payment.token,
          amount: rawParsed.amount,
          pay_token: rawParsed.pay_token
        })
      });

      const remoteData = await statusResponse.json();

      if (remoteData.status === "SUCCESS") {
        const finalReceiptUrl = txnid || remoteData.txnid || payment.invoice_url;

        // 1. Mise à jour de la table payments (verrou anti-doublon)
        const updateResult = await env.DB.prepare(
          "UPDATE payments SET status = 'completed', invoice_url = ? WHERE token = ? AND status = 'pending'"
        ).bind(finalReceiptUrl, payment.token).run();

        // 2. Si la mise à jour a réussi, déblocage de l'accès au document dans la table paniers
        if (updateResult.success && updateResult.meta && updateResult.meta.changes > 0) {
          const userId = rawParsed.userId;
          const docId = rawParsed.docId;

          const panierRecord = await env.DB.prepare(
            "SELECT achats FROM paniers WHERE userId = ?"
          ).bind(userId).first();

          const achats = panierRecord?.achats ? JSON.parse(panierRecord.achats) : {};

          achats[docId] = {
            purchaseDate: new Date().toISOString(),
            expiresAt: addMonths(CONFIG.ACCESS_DURATION_MONTHS),
            paymentMethod: "orange_money",
            token_transaction: payment.token,
            receipt_url: finalReceiptUrl
          };

          await env.DB.prepare(
            `INSERT INTO paniers (userId, achats) VALUES (?, ?)
             ON CONFLICT(userId) DO UPDATE SET achats = excluded.achats`
          ).bind(userId, JSON.stringify(achats)).run();
        }
      }
    } else if (status === "FAILED") {
      await env.DB.prepare("UPDATE payments SET status = 'failed' WHERE token = ?").bind(payment.token).run();
    }

    return json(request, { success: true, message: "Notification traitée avec succès" }, 200);

  } catch (error) {
    console.error("Erreur S2S PDF Webhook Orange:", error);
    return serverError(request, error);
  }
}
__name(s2sPdfWebhookHandler, "s2sPdfWebhookHandler");

async function getDocumentKeyHandler(request, env, docId) {
  try {
    const user = await verifyFirebaseToken(request);
    const doc = await getDocument(env, docId);
    if (!doc) return notFound(request, "Document introuvable.");
    if (doc.type === "payant") {
      const result = await env.DB.prepare(
        `SELECT achats FROM paniers WHERE userId = ?`
      ).bind(user.uid).first();
      const achats = result?.achats ? JSON.parse(result.achats) : {};
      const access = achats[docId];
      if (!access) return forbidden(request, "Accès refusé.");
      const now = new Date();
      const expiry = new Date(access.expiresAt);
      if (expiry < now) return forbidden(request, "Accès expiré.");
    }
    const key = await decryptDocumentKey(doc.encryptedKey, env.APP_SECRET_KEY);
    return success(request, { key, algorithm: "AES-GCM" });
  } catch (error) {
    return serverError(request, error);
  }
}
__name(getDocumentKeyHandler, "getDocumentKeyHandler");

async function getAuthorDashboardHandler(request, env) {
  try {
    const user = await verifyFirebaseToken(request);

    const { results: authorDocs } = await env.DB.prepare(
      `SELECT id, title, brutPrice, price, secretAuthorPhone FROM documents WHERE userId = ?`
    ).bind(user.uid).all();

    if (!authorDocs || authorDocs.length === 0) {
      return success(request, { totalRevenue: 0, totalSales: 0, invoices: [], phone: null, periodStart: null });
    }

    const authorPhone = authorDocs[0].secretAuthorPhone; 
    const docIds = authorDocs.map(d => d.id);
    const docMap = authorDocs.reduce((acc, d) => { acc[d.id] = d; return acc; }, {});

    const { results: allPaniers } = await env.DB.prepare(`SELECT achats FROM paniers`).all();

    let totalRevenue = 0;
    let totalSales = 0;
    const invoices = [];

    const now = new Date();
    let lastResetDate;
    
    if (now.getUTCDate() >= 15) {
        lastResetDate = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 15, 0, 0, 0));
    } else {
        lastResetDate = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - 1, 15, 0, 0, 0));
    }

    const resetTimestamp = lastResetDate.getTime();

    allPaniers.forEach(panier => {
      if (!panier.achats) return;
      
      let achats;
      try {
        achats = typeof panier.achats === 'string' ? JSON.parse(panier.achats) : panier.achats;
      } catch (e) {
        return;
      }
      
      for (const [docId, data] of Object.entries(achats)) {
        if (docIds.includes(docId)) {
          const purchaseTime = new Date(data.purchaseDate).getTime();
          
          if (!isNaN(purchaseTime) && purchaseTime >= resetTimestamp) {
              const doc = docMap[docId];
              const rawPrice = doc.brutPrice || doc.price;
              
              const price = Number(String(rawPrice).replace(/[^0-9]/g, '')) || 0;
              const partAuteur = Math.round(price * 0.58); 

              totalSales++;
              totalRevenue += partAuteur;

              invoices.push({
                docTitle: doc.title,
                purchaseDate: data.purchaseDate,
                revenue: partAuteur,
                paymentMethod: data.paymentMethod,
                receipt_url: data.receipt_url
              });
          }
        }
      }
    });

    invoices.sort((a, b) => new Date(b.purchaseDate) - new Date(a.purchaseDate));

    return success(request, { 
        totalRevenue, 
        totalSales, 
        invoices, 
        phone: authorPhone,
        periodStart: lastResetDate.toISOString()
    });
  } catch (error) {
    return serverError(request, error);
  }
}
__name(getAuthorDashboardHandler, "getAuthorDashboardHandler");

async function processMonthlyPayouts(env) {
  try {
    const now = new Date();
    
    const endDate = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 15, 23, 59, 59));
    
    let startMonth = now.getUTCMonth() - 1;
    let startYear = now.getUTCFullYear();
    if (startMonth < 0) {
      startMonth = 11;
      startYear--;
    }
    const startDate = new Date(Date.UTC(startYear, startMonth, 16, 0, 0, 0));

    const startTime = startDate.getTime();
    const endTime = endDate.getTime();

    const { results: allDocs } = await env.DB.prepare(
      `SELECT id, brutPrice, price, secretAuthorPhone FROM documents`
    ).all();
    
    const docMap = {};
    allDocs.forEach(d => {
      const rawPrice = d.brutPrice || d.price;
      const price = Number(String(rawPrice).replace(/[^0-9]/g, '')) || 0;
      docMap[d.id] = {
        phone: d.secretAuthorPhone,
        partAuteur: Math.round(price * 0.58)
      };
    });

    const { results: allPaniers } = await env.DB.prepare(`SELECT achats FROM paniers`).all();
    const payouts = {};

    allPaniers.forEach(panier => {
      if (!panier.achats) return;
      
      let achats;
      try {
        achats = typeof panier.achats === 'string' ? JSON.parse(panier.achats) : panier.achats;
      } catch (e) {
        return;
      }
      
      for (const [docId, data] of Object.entries(achats)) {
        const purchaseTime = new Date(data.purchaseDate).getTime();
        
        if (!isNaN(purchaseTime) && purchaseTime >= startTime && purchaseTime <= endTime) {
          const docInfo = docMap[docId];
          if (docInfo && docInfo.phone) {
            if (!payouts[docInfo.phone]) payouts[docInfo.phone] = 0;
            payouts[docInfo.phone] += docInfo.partAuteur;
          }
        }
      }
    });

    const payoutUrl = "https://api.ika-book.com/s2s/payout-authors"; 

    const payoutPayload = Object.entries(payouts)
        .map(([phone, amount]) => ({ phone, amount }))
        .filter(p => p.amount > 0);

    if (payoutPayload.length > 0) {
       const response = await fetch(payoutUrl, {
          method: "POST",
          headers: { 
            "Content-Type": "application/json",
            "x-server-key": env.S2S_SECRET_KEY 
          },
          body: JSON.stringify({ payouts: payoutPayload })
       });

       if (!response.ok) {
           console.error("Erreur lors de la requête de push manuel :", await response.text());
       } else {
           console.log("Paiements push initiés avec succès !");
       }
    }
  } catch (err) {
    console.error("Erreur fatale dans la tâche CRON de paiement :", err);
  }
}
__name(processMonthlyPayouts, "processMonthlyPayouts");

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const path = url.pathname;
      const method = request.method;

      if (method === "OPTIONS") {
        return handleOptions(request);
      }

      if (method === "POST" && path === "/s2s/pdf") {
        return await s2sPdfWebhookHandler(request, env);
      }

      if (method === "GET" && path === "/documents") {
        return getDocumentsHandler(request, env);
      }
      if (method === "POST" && path === "/api/upload") {
        return uploadHandler(request, env);
      }
      if (method === "GET" && path.startsWith("/api/download/")) {
        const fileName = path.replace("/api/download/", "");
        return downloadHandler(request, env, fileName);
      }
      if (method === "GET" && path === "/panier") {
        return getPanierHandler(request, env);
      }
      if (method === "POST" && path === "/panier") {
        return savePanierHandler(request, env);
      }
      if (method === "POST" && path === "/api/grant-access") {
        return grantAccessHandler(request, env);
      }
      if (method === "POST" && path === "/api/pay-and-distribute") {
        return await initiatePdfPaymentHandler(request, env);
      }
      if (method === "GET" && path.startsWith("/api/get-key/")) {
        const docId = path.replace("/api/get-key/", "");
        return getDocumentKeyHandler(request, env, docId);
      }
      if (method === "GET" && path === "/api/author-dashboard") {
        return await getAuthorDashboardHandler(request, env);
      }

      return notFound(request, "Route introuvable.");
    } catch (error) {
      return serverError(request, error);
    }
  },

  async scheduled(event, env, ctx) {
    ctx.waitUntil(processMonthlyPayouts(env));
  }
};
