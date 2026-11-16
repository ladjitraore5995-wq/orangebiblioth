var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// ====================================================================
// 1. CONFIGURATION ET ENDPOINTS (MODE PRODUCTION MALI)
// ====================================================================
var CONFIG = {
  FIREBASE_PROJECT_ID: "lt-coaching",
  JWKS_URL: "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com",
  JWKS_CACHE_DURATION: 6 * 60 * 60 * 1e3,
  ACCESS_DURATION_MONTHS: 9,
  MAX_DOCUMENTS: 50,
  MAX_FILE_SIZE: 100 * 1024 * 1024,
  PDF_MIME_TYPE: "application/pdf"
};

// Comptes administrateurs autorisés à voir tous les auteurs et les reversements
var ADMIN_EMAILS = [
  "ladjitraore5995@gmail.com",
  "fatmariamtraore95@gmail.com"
];

// Endpoints Orange Money WebPayment API - Production Mali (/ml/)
var ORANGE_OAUTH_API = "https://api.orange.com/oauth/v3/token";
var ORANGE_WEBPAY_API = "https://api.orange.com/orange-money-webpay/ml/v1/webpayment";
var ORANGE_STATUS_API = "https://api.orange.com/orange-money-webpay/ml/v1/transactionstatus";

var ALLOWED_ORIGINS = [
  "https://ika-book.com",
  "https://www.ika-book.com",
  "https://lt-coaching-biblio.pages.dev"
];

var cachedJwks = null;
var cachedJwksTime = 0;
var encoder = new TextEncoder();
var decoder = new TextDecoder();

// ====================================================================
// 2. CLASSES D'ERREURS & HELPER RESPONSES (FILTRAGE STRICT)
// ====================================================================
class AuthError extends Error {
  constructor(message = "Authentification requise ou session expirée.") {
    super(message);
    this.name = "AuthError";
  }
}
__name(AuthError, "AuthError");

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
      "Content-Type": "application/json",
      "X-Content-Type-Options": "nosniff"
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

function badRequest(request, message = "Requête invalide.") {
  return json(request, { success: false, error: message }, 400);
}
__name(badRequest, "badRequest");

function unauthorized(request, message = "Authentification requise ou session expirée.") {
  return json(request, { success: false, error: message }, 401);
}
__name(unauthorized, "unauthorized");

function forbidden(request, message = "Accès refusé.") {
  return json(request, { success: false, error: message }, 403);
}
__name(forbidden, "forbidden");

function notFound(request, message = "Ressource introuvable.") {
  return json(request, { success: false, error: message }, 404);
}
__name(notFound, "notFound");

// Filtre centralisé : ne renvoie JAMAIS error.message, stack trace ou erreur SQL au client
function serverError(request, error) {
  if (error instanceof AuthError) {
    return unauthorized(request, error.message);
  }

  console.error("[INTERNAL_SERVER_ERROR]", {
    name: error?.name || "Error",
    message: error?.message || String(error),
    stack: error?.stack || null
  });

  return json(
    request,
    {
      success: false,
      error: "Une erreur interne est survenue. Veuillez réessayer ultérieurement."
    },
    500
  );
}
__name(serverError, "serverError");

// ====================================================================
// 3. ENCODAGE / CHIFFREMENT CRYPTO
// ====================================================================
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
  return file && file.type === CONFIG.PDF_MIME_TYPE;
}
__name(isPdf, "isPdf");

function isValidFileSize(file) {
  return file && file.size > 0 && file.size <= CONFIG.MAX_FILE_SIZE;
}
__name(isValidFileSize, "isValidFileSize");

async function getMasterKey(secretKey) {
  if (!secretKey) {
    throw new Error("APP_SECRET_KEY manquante dans l'environnement.");
  }
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

// ====================================================================
// 4. AUTHENTIFICATION FIREBASE JWT (VERIFICATION SYSTÉMATIQUE)
// ====================================================================
async function getJwks() {
  const now = Date.now();
  if (!cachedJwks || now - cachedJwksTime > CONFIG.JWKS_CACHE_DURATION) {
    const response = await fetch(CONFIG.JWKS_URL);
    if (!response.ok) {
      throw new Error(`Échec récupération JWKS (${response.status})`);
    }
    cachedJwks = await response.json();
    cachedJwksTime = now;
  }
  return cachedJwks;
}
__name(getJwks, "getJwks");

async function verifyFirebaseToken(request) {
  const authorization = request.headers.get("Authorization");

  if (!authorization || !authorization.startsWith("Bearer ")) {
    throw new AuthError("Jeton d'authentification manquant ou invalide.");
  }

  const token = authorization.substring(7).trim();
  if (!token || token === "null" || token === "undefined") {
    throw new AuthError("Jeton d'authentification manquant ou invalide.");
  }

  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new AuthError("Jeton d'authentification invalide.");
  }

  let header;
  let payload;
  let signatureBytes;
  try {
    header = JSON.parse(base64UrlDecode(parts[0]));
    payload = JSON.parse(base64UrlDecode(parts[1]));
    signatureBytes = Uint8Array.from(base64UrlDecode(parts[2]), (c) => c.charCodeAt(0));
  } catch (e) {
    throw new AuthError("Jeton d'authentification mal formé.");
  }

  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== "number" || payload.exp <= now) {
    throw new AuthError("Session expirée. Veuillez vous reconnecter.");
  }
  if (payload.aud !== CONFIG.FIREBASE_PROJECT_ID) {
    throw new AuthError("Jeton d'authentification non autorisé.");
  }
  if (payload.iss !== `https://securetoken.google.com/${CONFIG.FIREBASE_PROJECT_ID}`) {
    throw new AuthError("Jeton d'authentification non autorisé.");
  }

  const uid = payload.user_id || payload.sub;
  if (!uid || typeof uid !== "string") {
    throw new AuthError("Identifiant utilisateur introuvable dans le jeton.");
  }

  const jwks = await getJwks();
  const jwk = jwks.keys.find((key) => key.kid === header.kid);
  if (!jwk) {
    throw new AuthError("Signature du jeton impossible à vérifier.");
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
    signatureBytes,
    encoder.encode(`${parts[0]}.${parts[1]}`)
  );

  if (!valid) {
    throw new AuthError("Signature du jeton invalide.");
  }

  return {
    uid,
    email: payload.email || null,
    payload
  };
}
__name(verifyFirebaseToken, "verifyFirebaseToken");

function isAdminUser(user) {
  return Boolean(
    user &&
    user.email &&
    ADMIN_EMAILS.includes(String(user.email).toLowerCase().trim())
  );
}
__name(isAdminUser, "isAdminUser");

// ====================================================================
// 5. SERVICES ORANGE MONEY
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
    console.error("[ORANGE_OAUTH_NON_JSON]", responseText);
    throw new Error("Réponse invalide du prestataire de paiement.");
  }

  if (!tokenData.access_token) {
    console.error("[ORANGE_OAUTH_FAILED]", { status: tokenResponse.status, body: responseText });
    throw new Error("Impossible d'initialiser la session de paiement.");
  }

  return tokenData.access_token;
}
__name(getOrangeAccessToken, "getOrangeAccessToken");

// ====================================================================
// 6. GESTION DES DOCUMENTS D1 & R2
// ====================================================================
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

async function uploadHandler(request, env, user) {
  try {
    const formData = await request.formData();
    const file = formData.get("file");

    if (!file || typeof file === "string") return badRequest(request, "Fichier manquant.");
    if (!isPdf(file)) return badRequest(request, "Seuls les fichiers PDF sont autorisés.");
    if (!isValidFileSize(file)) return badRequest(request, "La taille du fichier dépasse la limite autorisée.");

    const documentKey = String(formData.get("documentKey") || "").trim();
    const title = String(formData.get("title") || "").trim();
    const author = String(formData.get("author") || "").trim();
    const type = String(formData.get("type") || "").trim();
    const price = String(formData.get("price") || "").trim();
    const brutPrice = String(formData.get("brutPrice") || "0").trim();
    const phone = String(formData.get("phone") || "").trim();
    const operator = String(formData.get("operator") || "").trim();

    if (!documentKey) return badRequest(request, "Clé du document manquante.");
    if (!title || !author) return badRequest(request, "Le titre et l'auteur sont obligatoires.");
    if (!["gratuit", "payant"].includes(type)) return badRequest(request, "Régime d'accès invalide.");
    if (type === "payant" && (!phone || Number(brutPrice) <= 0)) {
      return badRequest(request, "Le prix et le numéro Mobile Money sont obligatoires pour un document payant.");
    }

    const documentId = generateDocumentId();
    const fileName = generateFileName(documentId);

    await env.MON_BUCKET.put(fileName, await file.arrayBuffer(), {
      httpMetadata: { contentType: CONFIG.PDF_MIME_TYPE }
    });

    const encryptedKey = await encryptDocumentKey(documentKey, env.APP_SECRET_KEY);

    await saveDocument(env, {
      id: documentId,
      title,
      author,
      type,
      price: type === "payant" ? price : "Gratuit",
      brutPrice: type === "payant" ? brutPrice : "0",
      phone: type === "payant" ? phone : "",
      operator: type === "payant" ? operator : "",
      fileName,
      encryptedKey,
      dateCreation: new Date().toISOString(),
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
    if (
      !fileName ||
      !fileName.endsWith(".pdf") ||
      fileName.includes("/") ||
      fileName.includes("..")
    ) {
      return badRequest(request, "Nom de fichier invalide.");
    }

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

// ====================================================================
// 7. GESTION DU PANIER & DE L'ACCÈS
// ====================================================================
async function getPanierHandler(request, env, user) {
  try {
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

async function savePanierHandler(request, env, user) {
  try {
    let body;
    try {
      body = await request.json();
    } catch (e) {
      return badRequest(request, "Format de requête invalide.");
    }

    if (!body || typeof body !== "object") return badRequest(request, "Données invalides.");
    if (!body.achats || typeof body.achats !== "object" || Array.isArray(body.achats)) {
      return badRequest(request, "Panier invalide.");
    }

    await env.DB.prepare(
      `INSERT INTO paniers (userId, achats) VALUES (?, ?)
       ON CONFLICT(userId) DO UPDATE SET achats = excluded.achats`
    ).bind(user.uid, JSON.stringify(body.achats)).run();

    return success(request, { success: true, message: "Panier mis à jour." });
  } catch (error) {
    return serverError(request, error);
  }
}
__name(savePanierHandler, "savePanierHandler");

async function grantAccessHandler(request, env) {
  try {
    const serverKey = request.headers.get("x-server-key");
    const isValidServerKey =
      typeof env.S2S_SECRET_KEY === "string" &&
      env.S2S_SECRET_KEY.length > 0 &&
      serverKey === env.S2S_SECRET_KEY;

    let authenticatedUser = null;
    if (!isValidServerKey) {
      authenticatedUser = await verifyFirebaseToken(request);
    }

    let body;
    try {
      body = await request.json();
    } catch (e) {
      return badRequest(request, "Format de requête invalide.");
    }

    const docId = body?.docId;
    if (!docId || typeof docId !== "string") return badRequest(request, "Identifiant du document manquant.");

    let userId;
    if (isValidServerKey) {
      if (!body.userId || typeof body.userId !== "string") {
        return badRequest(request, "Identifiant utilisateur manquant.");
      }
      userId = body.userId;
    } else {
      userId = authenticatedUser.uid;
    }

    const result = await env.DB.prepare(
      `SELECT achats FROM paniers WHERE userId = ?`
    ).bind(userId).first();
    const achats = result?.achats ? JSON.parse(result.achats) : {};

    achats[docId] = {
      purchaseDate: new Date().toISOString(),
      expiresAt: addMonths(CONFIG.ACCESS_DURATION_MONTHS),
      paymentMethod: isValidServerKey ? "server" : "firebase"
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
// 8. LOGIQUE PAIEMENT ORANGE MONEY PDF : POST /api/pay-and-distribute
// ====================================================================
async function initiatePdfPaymentHandler(request, env, user) {
  try {
    if (!env.ORANGE_MERCHANT_KEY) {
      throw new Error("ORANGE_MERCHANT_KEY manquante dans la configuration.");
    }

    let body;
    try {
      body = await request.json();
    } catch (e) {
      return badRequest(request, "Format de requête invalide.");
    }

    const docId = body?.docId;
    if (!docId || typeof docId !== "string") return badRequest(request, "Identifiant du document manquant.");

    const doc = await getDocument(env, docId);
    if (!doc) return notFound(request, "Document introuvable.");
    if (doc.type !== "payant") return badRequest(request, "Ce document est gratuit.");

    const rawPrice = doc.brutPrice || doc.price;
    if (!rawPrice) return badRequest(request, "Tarif du document non configuré.");

    const cleanPriceString = String(rawPrice).replace(/[^0-9]/g, "");
    const price = Number(cleanPriceString);

    if (isNaN(price) || price <= 0) return badRequest(request, "Tarif du document invalide.");

    const accessToken = await getOrangeAccessToken(env);
    const order_id = `PDF_${Date.now()}_${Math.floor(Math.random() * 10000)}`;
    const url = new URL(request.url);

    // Envoi de la demande de paiement à Orange Money Mali (XOF)
    const payResponse = await fetch(ORANGE_WEBPAY_API, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${accessToken}`,
        "Accept": "application/json",
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        merchant_key: env.ORANGE_MERCHANT_KEY,
        currency: "XOF",
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

      await env.DB.prepare(
        "INSERT OR REPLACE INTO payments (token, status, invoice_url, raw_data) VALUES (?, ?, ?, ?)"
      ).bind(order_id, "pending", data.payment_url || "", rawMetadata).run();

      return success(request, {
        success: true,
        message: "Facture générée avec succès.",
        invoice_url: data.payment_url,
        token: order_id,
        pay_token: data.pay_token
      });
    } else {
      console.error("[ORANGE_WEBPAY_REJECTED]", data);
      return badRequest(request, "Impossible d'initialiser le paiement Mobile Money.");
    }
  } catch (error) {
    return serverError(request, error);
  }
}
__name(initiatePdfPaymentHandler, "initiatePdfPaymentHandler");

// ====================================================================
// 9. WEBHOOK NOTIFICATION ORANGE MONEY : POST /s2s/pdf
// ====================================================================
async function s2sPdfWebhookHandler(request, env) {
  try {
    let body = {};
    const url = new URL(request.url);
    const contentType = request.headers.get("content-type") || "";

    try {
      if (contentType.includes("application/json")) {
        body = await request.json();
      } else if (contentType.includes("application/x-www-form-urlencoded")) {
        const formData = await request.formData();
        for (const [key, value] of formData.entries()) {
          body[key] = value;
        }
      } else {
        const text = await request.text();
        const params = new URLSearchParams(text);
        for (const [key, value] of params.entries()) {
          body[key] = value;
        }
      }
    } catch (e) {
      console.error("[WEBHOOK_PARSE_ERROR]", e);
    }

    const notif_token = String(body.notif_token || body.notifToken || url.searchParams.get("notif_token") || "").trim();
    const order_id = String(body.order_id || body.orderId || body.token || url.searchParams.get("order_id") || "").trim();
    const txnid = String(body.txnid || body.txn_id || body.transaction_id || "").trim();
    const rawStatus = String(body.status || body.state || "").toUpperCase();

    if (!notif_token && !order_id) {
      return badRequest(request, "Identifiant de transaction manquant.");
    }

    const { results } = await env.DB.prepare(
      "SELECT * FROM payments WHERE json_extract(raw_data, '$.notif_token') = ? OR token = ?"
    ).bind(notif_token, order_id).all();

    if (!results || results.length === 0) {
      return notFound(request, "Transaction introuvable.");
    }

    const payment = results[0];
    let rawParsed = {};
    try {
      rawParsed = JSON.parse(payment.raw_data || "{}");
    } catch (e) {
      console.error("[PAYMENT_METADATA_CORRUPTED]", payment.token);
    }

    // Vérification du jeton de notification secret s'il est enregistré
    if (rawParsed.notif_token && notif_token && rawParsed.notif_token !== notif_token) {
      return forbidden(request, "Signature de notification invalide.");
    }

    const isSuccessStatus = ["SUCCESS", "SUCCESSFUL", "COMPLETED", "200", "00"].includes(rawStatus);
    const isFailedStatus = ["FAILED", "EXPIRED", "CANCELLED", "REFUNDED"].includes(rawStatus);

    if (payment.status !== "completed" && isSuccessStatus) {
      let verified = false;
      let finalReceiptUrl = txnid || payment.invoice_url;

      try {
        const accessToken = await getOrangeAccessToken(env);
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

        if (statusResponse.ok) {
          const remoteData = await statusResponse.json();
          const remoteStatus = (remoteData.status || "").toUpperCase();
          if (["SUCCESS", "SUCCESSFUL", "COMPLETED", "200"].includes(remoteStatus)) {
            verified = true;
            finalReceiptUrl = remoteData.txnid || txnid || payment.invoice_url;
          }
        }
      } catch (authErr) {
        console.warn("[ORANGE_STATUS_UNREACHABLE] Validation via webhook direct :", authErr?.message);
        verified = true;
      }

      if (verified) {
        const updateResult = await env.DB.prepare(
          "UPDATE payments SET status = 'completed', invoice_url = ? WHERE token = ? AND status != 'completed'"
        ).bind(finalReceiptUrl, payment.token).run();

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
    } else if (isFailedStatus) {
      await env.DB.prepare("UPDATE payments SET status = 'failed' WHERE token = ?").bind(payment.token).run();
    }

    return success(request, { success: true, message: "Notification enregistrée." });
  } catch (error) {
    return serverError(request, error);
  }
}
__name(s2sPdfWebhookHandler, "s2sPdfWebhookHandler");

// ====================================================================
// 10. CLÉ DU DOCUMENT ET TABLEAU DE BORD AUTEUR / ADMIN
// ====================================================================
async function getDocumentKeyHandler(request, env, docId, user) {
  try {
    if (!docId) return badRequest(request, "Identifiant du document manquant.");

    const doc = await getDocument(env, docId);
    if (!doc) return notFound(request, "Document introuvable.");

    if (doc.type === "payant" && !isAdminUser(user)) {
      const result = await env.DB.prepare(
        `SELECT achats FROM paniers WHERE userId = ?`
      ).bind(user.uid).first();
      const achats = result?.achats ? JSON.parse(result.achats) : {};
      const access = achats[docId];
      if (!access) return forbidden(request, "Accès refusé à ce document.");

      const now = new Date();
      const expiry = new Date(access.expiresAt);
      if (expiry < now) return forbidden(request, "Votre accès à ce document a expiré.");
    }

    const key = await decryptDocumentKey(doc.encryptedKey, env.APP_SECRET_KEY);
    return success(request, { key, algorithm: "AES-GCM" });
  } catch (error) {
    return serverError(request, error);
  }
}
__name(getDocumentKeyHandler, "getDocumentKeyHandler");

async function getAuthorDashboardHandler(request, env, user, forceAdminView = false) {
  try {
    const isAdmin = isAdminUser(user);
    if (forceAdminView && !isAdmin) {
      return forbidden(request, "Accès refusé. Réservé aux administrateurs.");
    }

    const { results: authorDocs } = isAdmin
      ? await env.DB.prepare(
          `SELECT id, title, author, brutPrice, price, secretAuthorPhone, secretMobileMoneyOperator, userId FROM documents`
        ).all()
      : await env.DB.prepare(
          `SELECT id, title, author, brutPrice, price, secretAuthorPhone, secretMobileMoneyOperator, userId FROM documents WHERE userId = ?`
        ).bind(user.uid).all();

    if (!authorDocs || authorDocs.length === 0) {
      return success(request, {
        isAdmin,
        totalRevenue: 0,
        totalSales: 0,
        invoices: [],
        authorsSummary: [],
        phone: isAdmin ? "Tous les auteurs (Vue Admin)" : null,
        periodStart: null
      });
    }

    const authorPhone = isAdmin ? "Tous les auteurs (Vue Admin)" : authorDocs[0].secretAuthorPhone;
    const docIds = authorDocs.map((d) => d.id);
    const docMap = authorDocs.reduce((acc, d) => {
      acc[d.id] = d;
      return acc;
    }, {});

    const { results: allPaniers } = await env.DB.prepare(`SELECT achats FROM paniers`).all();

    let totalRevenue = 0;
    let totalSales = 0;
    const invoices = [];
    const authorsMap = {};

    const now = new Date();
    let lastResetDate;

    if (now.getUTCDate() >= 15) {
      lastResetDate = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 15, 0, 0, 0));
    } else {
      lastResetDate = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - 1, 15, 0, 0, 0));
    }

    const resetTimestamp = lastResetDate.getTime();

    allPaniers.forEach((panier) => {
      if (!panier.achats) return;

      let achats;
      try {
        achats = typeof panier.achats === "string" ? JSON.parse(panier.achats) : panier.achats;
      } catch (e) {
        return;
      }

      for (const [docId, data] of Object.entries(achats)) {
        if (docIds.includes(docId)) {
          const purchaseTime = new Date(data.purchaseDate).getTime();

          if (!isNaN(purchaseTime) && purchaseTime >= resetTimestamp) {
            const doc = docMap[docId];
            const rawPrice = doc.brutPrice || doc.price;

            const price = Number(String(rawPrice).replace(/[^0-9]/g, "")) || 0;
            const partAuteur = Math.round(price * 0.58);

            totalSales++;
            totalRevenue += partAuteur;

            const keyAuthor = doc.secretAuthorPhone || doc.userId || "Inconnu";
            if (!authorsMap[keyAuthor]) {
              authorsMap[keyAuthor] = {
                authorName: doc.author || "Auteur",
                phone: doc.secretAuthorPhone || "Non renseigné",
                operator: doc.secretMobileMoneyOperator || "Non renseigné",
                userId: doc.userId,
                salesCount: 0,
                totalRevenue: 0
              };
            }
            authorsMap[keyAuthor].salesCount++;
            authorsMap[keyAuthor].totalRevenue += partAuteur;

            invoices.push({
              docTitle: isAdmin
                ? `${doc.title} (${doc.author || "Auteur"} - ${doc.secretAuthorPhone || "N/A"})`
                : doc.title,
              authorName: doc.author,
              authorPhone: doc.secretAuthorPhone,
              operator: doc.secretMobileMoneyOperator,
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
    const authorsSummary = Object.values(authorsMap).sort((a, b) => b.totalRevenue - a.totalRevenue);

    return success(request, {
      isAdmin,
      totalRevenue,
      totalSales,
      invoices,
      authorsSummary,
      phone: authorPhone,
      periodStart: lastResetDate.toISOString()
    });
  } catch (error) {
    return serverError(request, error);
  }
}
__name(getAuthorDashboardHandler, "getAuthorDashboardHandler");

// ====================================================================
// 11. TÂCHE AUTOMATIQUE CRON (ÉCRITURE D1 QUOTIDIENNE & MENSUELLE) + ROUTE ADMIN
// ====================================================================
async function ensurePayoutsTable(env) {
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS author_payouts (
      id TEXT PRIMARY KEY,
      period_type TEXT NOT NULL,
      period_key TEXT NOT NULL,
      author_phone TEXT NOT NULL,
      author_name TEXT,
      operator TEXT,
      sales_count INTEGER DEFAULT 0,
      total_amount INTEGER DEFAULT 0,
      updated_at TEXT NOT NULL
    )
  `).run();
}
__name(ensurePayoutsTable, "ensurePayoutsTable");

async function processMonthlyPayouts(env) {
  try {
    await ensurePayoutsTable(env);

    const now = new Date();
    const nowIso = now.toISOString();

    const dailyStart = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), 0, 0, 0, 0));
    const dailyEnd = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), 23, 59, 59, 999));
    const dailyStartTime = dailyStart.getTime();
    const dailyEndTime = dailyEnd.getTime();
    const dailyPeriodKey = dailyStart.toISOString().slice(0, 10);

    let monthlyStart;
    let monthlyEnd;
    if (now.getUTCDate() >= 16) {
      monthlyStart = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 16, 0, 0, 0, 0));
      monthlyEnd = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 15, 23, 59, 59, 999));
    } else {
      monthlyStart = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - 1, 16, 0, 0, 0, 0));
      monthlyEnd = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 15, 23, 59, 59, 999));
    }
    const monthlyStartTime = monthlyStart.getTime();
    const monthlyEndTime = monthlyEnd.getTime();
    const monthlyPeriodKey = `${monthlyStart.toISOString().slice(0, 10)}_au_${monthlyEnd.toISOString().slice(0, 10)}`;

    const { results: allDocs } = await env.DB.prepare(
      `SELECT id, author, brutPrice, price, secretAuthorPhone, secretMobileMoneyOperator FROM documents`
    ).all();

    const docMap = {};
    allDocs.forEach((d) => {
      const rawPrice = d.brutPrice || d.price;
      const price = Number(String(rawPrice).replace(/[^0-9]/g, "")) || 0;
      docMap[d.id] = {
        phone: d.secretAuthorPhone,
        authorName: d.author || "Auteur",
        operator: d.secretMobileMoneyOperator || "orange_money",
        partAuteur: Math.round(price * 0.58)
      };
    });

    const { results: allPaniers } = await env.DB.prepare(`SELECT achats FROM paniers`).all();
    const dailyPayouts = {};
    const monthlyPayouts = {};

    allPaniers.forEach((panier) => {
      if (!panier.achats) return;

      let achats;
      try {
        achats = typeof panier.achats === "string" ? JSON.parse(panier.achats) : panier.achats;
      } catch (e) {
        return;
      }

      for (const [docId, data] of Object.entries(achats)) {
        const purchaseTime = new Date(data.purchaseDate).getTime();
        if (isNaN(purchaseTime)) continue;

        const docInfo = docMap[docId];
        if (!docInfo || !docInfo.phone || docInfo.partAuteur <= 0) continue;

        if (purchaseTime >= dailyStartTime && purchaseTime <= dailyEndTime) {
          if (!dailyPayouts[docInfo.phone]) {
            dailyPayouts[docInfo.phone] = {
              phone: docInfo.phone,
              authorName: docInfo.authorName,
              operator: docInfo.operator,
              salesCount: 0,
              amount: 0
            };
          }
          dailyPayouts[docInfo.phone].salesCount += 1;
          dailyPayouts[docInfo.phone].amount += docInfo.partAuteur;
        }

        if (purchaseTime >= monthlyStartTime && purchaseTime <= monthlyEndTime) {
          if (!monthlyPayouts[docInfo.phone]) {
            monthlyPayouts[docInfo.phone] = {
              phone: docInfo.phone,
              authorName: docInfo.authorName,
              operator: docInfo.operator,
              salesCount: 0,
              amount: 0
            };
          }
          monthlyPayouts[docInfo.phone].salesCount += 1;
          monthlyPayouts[docInfo.phone].amount += docInfo.partAuteur;
        }
      }
    });

    for (const item of Object.values(dailyPayouts)) {
      if (item.amount > 0) {
        const rowId = `daily_${dailyPeriodKey}_${item.phone}`;
        await env.DB.prepare(`
          INSERT INTO author_payouts (
            id, period_type, period_key, author_phone, author_name, operator, sales_count, total_amount, updated_at
          ) VALUES (?, 'daily', ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(id) DO UPDATE SET
            author_name = excluded.author_name,
            operator = excluded.operator,
            sales_count = excluded.sales_count,
            total_amount = excluded.total_amount,
            updated_at = excluded.updated_at
        `).bind(
          rowId, dailyPeriodKey, item.phone, item.authorName, item.operator, item.salesCount, item.amount, nowIso
        ).run();
      }
    }

    for (const item of Object.values(monthlyPayouts)) {
      if (item.amount > 0) {
        const rowId = `monthly_${monthlyPeriodKey}_${item.phone}`;
        await env.DB.prepare(`
          INSERT INTO author_payouts (
            id, period_type, period_key, author_phone, author_name, operator, sales_count, total_amount, updated_at
          ) VALUES (?, 'monthly', ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(id) DO UPDATE SET
            author_name = excluded.author_name,
            operator = excluded.operator,
            sales_count = excluded.sales_count,
            total_amount = excluded.total_amount,
            updated_at = excluded.updated_at
        `).bind(
          rowId, monthlyPeriodKey, item.phone, item.authorName, item.operator, item.salesCount, item.amount, nowIso
        ).run();
      }
    }

    console.log(`[CRON_PAYOUTS_OK] daily=${dailyPeriodKey}, monthly=${monthlyPeriodKey}`);
  } catch (err) {
    console.error("[CRON_PAYOUTS_ERROR]", err);
  }
}
__name(processMonthlyPayouts, "processMonthlyPayouts");

async function getAdminPayoutsHandler(request, env, user) {
  try {
    if (!isAdminUser(user)) {
      return forbidden(request, "Accès refusé. Réservé aux administrateurs.");
    }

    await ensurePayoutsTable(env);

    const url = new URL(request.url);
    const typeFilter = url.searchParams.get("type");
    const periodFilter = url.searchParams.get("period");

    let query = `SELECT * FROM author_payouts`;
    const conditions = [];
    const bindings = [];

    if (typeFilter && ["daily", "monthly"].includes(typeFilter)) {
      conditions.push(`period_type = ?`);
      bindings.push(typeFilter);
    }
    if (periodFilter) {
      conditions.push(`period_key = ?`);
      bindings.push(periodFilter);
    }

    if (conditions.length > 0) {
      query += ` WHERE ` + conditions.join(" AND ");
    }
    query += ` ORDER BY period_key DESC, total_amount DESC`;

    const stmt = bindings.length > 0
      ? env.DB.prepare(query).bind(...bindings)
      : env.DB.prepare(query);

    const { results } = await stmt.all();

    return success(request, {
      success: true,
      count: results.length,
      payouts: results
    });
  } catch (error) {
    return serverError(request, error);
  }
}
__name(getAdminPayoutsHandler, "getAdminPayoutsHandler");

// ====================================================================
// 12. ROUTEUR PRINCIPAL AVEC GARDE D'AUTHENTIFICATION CENTRALISÉE
// ====================================================================
export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const path = url.pathname;
      const method = request.method;

      if (method === "OPTIONS") {
        return handleOptions(request);
      }

      // 1. Routes publiques / Webhook externe
      if (method === "POST" && path === "/s2s/pdf") {
        return await s2sPdfWebhookHandler(request, env);
      }
      if (method === "GET" && path === "/documents") {
        return await getDocumentsHandler(request, env);
      }
      if (method === "GET" && path.startsWith("/api/download/")) {
        const fileName = decodeURIComponent(path.replace("/api/download/", ""));
        return await downloadHandler(request, env, fileName);
      }

      // 2. Route hybride (Clé serveur S2S OU Jeton Firebase)
      if (method === "POST" && path === "/api/grant-access") {
        return await grantAccessHandler(request, env);
      }

      // 3. Vérification systématique du jeton Firebase pour toutes les routes sensibles
      if (
        path === "/api/upload" ||
        path === "/panier" ||
        path === "/api/pay-and-distribute" ||
        path.startsWith("/api/get-key/") ||
        path === "/api/author-dashboard" ||
        path.startsWith("/api/admin/")
      ) {
        const user = await verifyFirebaseToken(request);

        // Garde Administrateur systématique sur /api/admin/*
        if (path.startsWith("/api/admin/") && !isAdminUser(user)) {
          return forbidden(request, "Accès refusé. Privilèges administrateur requis.");
        }

        if (method === "POST" && path === "/api/upload") {
          return await uploadHandler(request, env, user);
        }
        if (method === "GET" && path === "/panier") {
          return await getPanierHandler(request, env, user);
        }
        if (method === "POST" && path === "/panier") {
          return await savePanierHandler(request, env, user);
        }
        if (method === "POST" && path === "/api/pay-and-distribute") {
          return await initiatePdfPaymentHandler(request, env, user);
        }
        if (method === "GET" && path.startsWith("/api/get-key/")) {
          const docId = decodeURIComponent(path.replace("/api/get-key/", ""));
          return await getDocumentKeyHandler(request, env, docId, user);
        }
        if (method === "GET" && path === "/api/author-dashboard") {
          return await getAuthorDashboardHandler(request, env, user, false);
        }
        if (method === "GET" && path === "/api/admin/authors-dashboard") {
          return await getAuthorDashboardHandler(request, env, user, true);
        }
        if (method === "GET" && path === "/api/admin/payouts") {
          return await getAdminPayoutsHandler(request, env, user);
        }
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
