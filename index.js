import { jwtVerify, createRemoteJWKSet } from 'jose';

// ====================================================================
// 1. CONSTANTES & CONFIGURATION
// ====================================================================

// Tarifs des packs de crédits (Crédits : Prix en FCFA)
const CREDIT_PACKS = {
  100: 300,
  200: 500,
  300: 750,
  1000: 2000
};

// Endpoints Orange Money API WebPayment
const ORANGE_OAUTH_API = "https://api.orange.com/oauth/v3/token";
const ORANGE_WEBPAY_API = "https://api.orange.com/orange-money-webpay/dev/v1/webpayment";
const ORANGE_STATUS_API = "https://api.orange.com/orange-money-webpay/dev/v1/transactionstatus";

// Clés publiques Google pour vérification des JWT Firebase
const JWKS = createRemoteJWKSet(
  new URL('https://www.googleapis.com/robot/v1/metadata/jwk/securetoken@system.gserviceaccount.com')
);

// Domaines autorisés pour les requêtes CORS
const ALLOWED_ORIGINS = [
  "https://ika-book.com",
  "https://www.ika-book.com",
  "https://lt-coaching-biblio.pages.dev"
];

// Limites de sécurité multimodale
const MAX_MULTIMODAL_SIZE_BYTES = 10 * 1024 * 1024; // 10 Mo
const ALLOWED_MIME_TYPES = [
  "audio/mp3", "audio/mpeg", "audio/wav", "audio/ogg",
  "image/png", "image/jpeg", "image/webp",
  "video/mp4"
];

// ====================================================================
// 2. MIDDLEWARES & UTILITAIRES DE SÉCURITÉ
// ====================================================================

function getCorsHeaders(request) {
  const origin = request.headers.get("Origin");
  const originToAllow = ALLOWED_ORIGINS.includes(origin) ? origin : "https://www.ika-book.com";
  return {
    "Access-Control-Allow-Origin": originToAllow,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, x-server-key",
  };
}

async function verifyFirebaseToken(request, firebaseProjectId) {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return { error: "Token d'authentification manquant ou mal formaté." };
  }
  
  const token = authHeader.split(' ')[1];
  try {
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: `https://securetoken.google.com/${firebaseProjectId}`,
      audience: firebaseProjectId,
      algorithms: ['RS256'],
    });
    return { user: payload };
  } catch (error) {
    console.error("[AUTH_ERROR] Échec de vérification du jeton JWT :", error.message);
    return { error: "Token invalide ou expiré." };
  }
}

/**
 * Validation de taille et de type MIME des charges utiles Base64
 */
function validateBase64File(base64Data, mimeType) {
  if (!base64Data || typeof base64Data !== 'string') {
    throw new Error("Données de fichier invalides.");
  }

  if (!mimeType || !ALLOWED_MIME_TYPES.includes(mimeType.toLowerCase())) {
    throw new Error(`Type de fichier non supporté ou non sécurisé : ${mimeType}`);
  }

  const pureBase64 = base64Data.includes(',') ? base64Data.split(',')[1] : base64Data;
  const estimatedSizeBytes = Math.ceil((pureBase64.length * 3) / 4);

  if (estimatedSizeBytes > MAX_MULTIMODAL_SIZE_BYTES) {
    throw new Error("Fichier trop volumineux. La taille maximale autorisée est de 10 Mo.");
  }

  return pureBase64;
}

function calculateCost(targetModel, aiData) {
  let cost = 0; 

  switch (targetModel) {
    case 'gemini-3.1-flash-lite-image':
    case 'gemini-3.1-flash-image':
      cost = 20; 
      break;
    case 'lyria-3.5':
      cost = 30; 
      break;
    case 'codegemini-3.6-flash':
    case 'gemini-3.6-flash':
    default:
      if (aiData && aiData.usage_metadata) {
        const inputTokens = aiData.usage_metadata.input_tokens || 0; 
        const outputTokens = aiData.usage_metadata.output_tokens || 0; 
        cost = (inputTokens / 1000) + (outputTokens / 700);
        if (cost < 0.5) cost = 0.5; 
      } else {
        cost = 1.5; 
      }
      break;
  }

  return cost;
}

async function callAI(apiKey, model, systemInstruction, prompt, history = [], audioData = null, mimeType = "audio/mp3") {
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;
  
  const rawHistory = Array.isArray(history) ? history.slice(-10) : [];
  const formattedHistory = rawHistory.map(msg => ({
    role: msg.role === 'assistant' || msg.role === 'model' ? 'model' : 'user',
    parts: [{ text: msg.content || msg.text || '' }]
  }));

  const userParts = [{ text: prompt }];

  if (audioData) {
    const validatedBase64 = validateBase64File(audioData, mimeType);
    userParts.push({
      inline_data: {
        mime_type: mimeType,
        data: validatedBase64
      }
    });
  }

  const contents = [...formattedHistory, { role: 'user', parts: userParts }];
  
  const payload = {
    contents: contents,
    generationConfig: { 
      temperature: 0.2,
      responseModalities: ["AUDIO", "TEXT"]
    } 
  };
  
  if (systemInstruction) {
    payload.system_instruction = { parts: [{ text: systemInstruction }] };
  }

  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });

  const data = await response.json();
  
  if (!response.ok) {
    console.error(`[AI_API_ERROR] ${model} :`, data);
    throw new Error("Le traitement IA a échoué. Veuillez réessayer.");
  }

  const candidate = data.candidates?.[0];
  if (!candidate || !candidate.content) {
    console.warn(`[AI_BLOCKED] Réponse filtrée :`, data.promptFeedback || candidate?.finishReason);
    throw new Error("Réponse filtrée par les règles de sécurité.");
  }

  let textResult = "";
  let audioBase64 = null;
  let audioMimeType = "audio/mp3";

  const parts = candidate.content.parts || [];
  for (const part of parts) {
    if (part.text) textResult += part.text;
    if (part.inlineData || part.inline_data) {
      const inline = part.inlineData || part.inline_data;
      audioBase64 = inline.data;
      audioMimeType = inline.mimeType || inline.mime_type || "audio/mp3";
    }
  }

  return {
    text: textResult,
    audioData: audioBase64,
    audioMimeType: audioMimeType,
    rawData: data
  };
}

// ====================================================================
// 3. SERVICES (BASE DE DONNÉES D1 & CRÉDITS ATOMIQUES)
// ====================================================================

async function setupDatabase(env) {
  await env.DB.batch([
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS users (uid TEXT PRIMARY KEY, email TEXT, credits REAL)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS payments (token TEXT PRIMARY KEY, status TEXT, invoice_url TEXT, raw_data TEXT)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS processed_transactions (token TEXT PRIMARY KEY, status TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`)
  ]);
}

async function syncAndGetUserCredits(env, uid, email) {
  const user = await env.DB.prepare("SELECT credits FROM users WHERE uid = ?").bind(uid).first();
  if (!user) {
    await env.DB.prepare("INSERT INTO users (uid, email, credits) VALUES (?, ?, ?)")
      .bind(uid, email, 10.0)
      .run();
    return 10.0;
  }
  return user.credits;
}

/**
 * Mises à jour SQL atomiques (élimine les Race Conditions)
 */
async function addCreditsDirectly(env, uid, amountToAdd) {
  const numericAmount = Number(amountToAdd);
  if (isNaN(numericAmount) || numericAmount <= 0) {
    throw new Error("Montant de crédits invalide.");
  }

  const result = await env.DB.prepare(
    `INSERT INTO users (uid, email, credits) VALUES (?, 'email_orange_inconnu', 10.0 + ?)
     ON CONFLICT(uid) DO UPDATE SET credits = credits + excluded.credits`
  ).bind(uid, numericAmount).run();

  return result.success;
}

async function deductCreditsDirectly(env, uid, amountToDeduct) {
  await env.DB.prepare(
    "UPDATE users SET credits = MAX(0, credits - ?) WHERE uid = ?"
  ).bind(amountToDeduct, uid).run();
}

// ====================================================================
// 4. LOGIQUE ORANGE MONEY
// ====================================================================

async function getOrangeAccessToken(env) {
  if (!env.ORANGE_AUTH_HEADER) {
    throw new Error("Configuration serveur incomplète : Clé d'authentification manquante.");
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

  if (!tokenResponse.ok) {
    const errText = await tokenResponse.text();
    console.error("[ORANGE_OAUTH_ERROR]", errText);
    throw new Error("Authentification auprès du service de paiement échouée.");
  }

  const tokenData = await tokenResponse.json();
  if (!tokenData.access_token) {
    throw new Error("Accès refusé par le prestataire de paiement.");
  }

  return tokenData.access_token;
}

async function handlePayCredits(request, user, corsHeaders, env) {
  try {
    if (!env.ORANGE_MERCHANT_KEY) {
      return new Response(JSON.stringify({ error: "Configuration marchande manquante." }), { status: 500, headers: corsHeaders });
    }

    let body;
    try {
      body = await request.json();
    } catch (e) {
      return new Response(JSON.stringify({ error: "Requête JSON invalide." }), { status: 400, headers: corsHeaders });
    }

    const { creditsRequested, userId } = body;

    if (!userId || userId !== user.sub) {
      return new Response(JSON.stringify({ error: "Utilisateur non autorisé." }), { status: 403, headers: corsHeaders });
    }

    const finalAmount = CREDIT_PACKS[creditsRequested];
    if (!finalAmount) {
      return new Response(JSON.stringify({ error: "Pack de crédits invalide." }), { status: 400, headers: corsHeaders });
    }

    const accessToken = await getOrangeAccessToken(env);
    const order_id = `CMD_${Date.now()}_${Math.floor(Math.random() * 10000)}`;

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
        amount: finalAmount,
        return_url: `https://www.ika-book.com/boutique.html`,
        cancel_url: `https://www.ika-book.com/boutique.html`,
        notif_url: `https://orangemoney.ladjitraore5995.workers.dev/notif`,
        lang: "fr",
        reference: "Ika-Book"
      })
    });

    const data = await payResponse.json();

    if (data.status === 201 || data.message === "OK") {
      const rawMetadata = JSON.stringify({
        userId: userId,
        creditsRequested: creditsRequested,
        pay_token: data.pay_token,
        notif_token: data.notif_token,
        amount: finalAmount
      });

      await env.DB.prepare("INSERT OR REPLACE INTO payments (token, status, invoice_url, raw_data) VALUES (?, ?, ?, ?)")
        .bind(order_id, "pending", data.payment_url || "", rawMetadata)
        .run();

      return new Response(JSON.stringify({ 
        success: true, 
        invoice_url: data.payment_url, 
        token: order_id, 
        pay_token: data.pay_token 
      }), { status: 200, headers: corsHeaders });

    } else {
      console.error("[ORANGE_PAY_ERROR]", data);
      return new Response(JSON.stringify({ error: "Création du paiement échouée." }), { status: 400, headers: corsHeaders });
    }
  } catch (error) {
    console.error("[PAYMENT_ERROR]", error);
    return new Response(JSON.stringify({ error: "Erreur serveur lors de l'initiation du paiement." }), { status: 500, headers: corsHeaders });
  }
}

async function handleOrangeWebhook(request, env, corsHeaders) {
  let body = {};
  try {
    body = await request.json();
  } catch (e) {
    return new Response(JSON.stringify({ error: "Payload invalide" }), { status: 400, headers: corsHeaders });
  }

  const { status, notif_token, txnid } = body;

  if (!notif_token) {
    return new Response(JSON.stringify({ error: "Token de notification manquant" }), { status: 400, headers: corsHeaders });
  }

  try {
    const { results } = await env.DB.prepare(
      "SELECT * FROM payments WHERE json_extract(raw_data, '$.notif_token') = ?"
    ).bind(notif_token).all();

    if (results && results.length > 0) {
      const payment = results[0];
      const rawParsed = JSON.parse(payment.raw_data);

      if (payment.status !== 'completed' && status === "SUCCESS") {
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

        const remoteData = await statusResponse.json();

        if (remoteData.status === "SUCCESS") {
          const finalInvoiceUrl = txnid || remoteData.txnid || payment.invoice_url;
          
          const updateResult = await env.DB.prepare(
            "UPDATE payments SET status = 'completed', invoice_url = ? WHERE token = ? AND status = 'pending'"
          ).bind(finalInvoiceUrl, payment.token).run();

          if (updateResult.success && updateResult.meta && updateResult.meta.changes > 0) {
            await addCreditsDirectly(env, rawParsed.userId, rawParsed.creditsRequested);
          }
        }
      } else if (status === "FAILED") {
        await env.DB.prepare("UPDATE payments SET status = 'failed' WHERE token = ?").bind(payment.token).run();
      }
    }
  } catch (e) {
    console.error("[WEBHOOK_ERROR]", e);
  }

  return new Response(JSON.stringify({ status: "Notification enregistrée." }), { status: 200, headers: corsHeaders });
}

// ====================================================================
// 5. SERVICES COMPLÉMENTAIRES (RECHERCHE WEB & CONVERSION POINTS)
// ====================================================================

async function handleWebSearch(request, user, corsHeaders, env) {
  const { query } = await request.json();

  if (!query) {
    return new Response(JSON.stringify({ error: "Requête manquante." }), { 
      status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } 
    });
  }

  const serperApiKey = env.SERPER_API_KEY;
  if (!serperApiKey) {
    return new Response(JSON.stringify({ error: "Service de recherche indisponible." }), { 
      status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } 
    });
  }

  try {
    const response = await fetch("https://google.serper.dev/search", {
      method: "POST",
      headers: {
        "X-API-KEY": serperApiKey,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ q: query, num: 4 })
    });

    const data = await response.json();
    const results = (data.organic || []).map(item => ({
      title: item.title,
      url: item.link,
      snippet: item.snippet
    }));

    return new Response(JSON.stringify({ success: true, results }), {
      status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  } catch (error) {
    console.error("[SERPER_ERROR]", error);
    return new Response(JSON.stringify({ error: "Échec de la recherche." }), {
      status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  }
}

async function handleConvertPoints(request, user, corsHeaders, env) {
  const { parrain_uid, points_to_remove, credits_to_add } = await request.json();

  if (user.sub !== parrain_uid) {
    return new Response(JSON.stringify({ error: "Non autorisé." }), { 
      status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } 
    });
  }

  if (!env.IKACREDIT_WORKER) {
    return new Response(JSON.stringify({ error: "Service de conversion non lié." }), { 
      status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } 
    });
  }

  const numPoints = Number(points_to_remove);
  const numCredits = Number(credits_to_add);

  if (isNaN(numPoints) || isNaN(numCredits) || numPoints <= 0 || numCredits <= 0) {
    return new Response(JSON.stringify({ error: "Valeurs de conversion invalides." }), { 
      status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } 
    });
  }

  const authHeader = request.headers.get("Authorization");
  
  const s2sResponse = await env.IKACREDIT_WORKER.fetch("https://ikacredit.ladjitraore5995.workers.dev/remove-points", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": authHeader 
    },
    body: JSON.stringify({
      parrain_uid: parrain_uid,
      points_to_remove: numPoints
    })
  });

  if (!s2sResponse.ok) {
    let errorMsg = "Échec lors du retrait des points.";
    try {
      const errData = await s2sResponse.json();
      errorMsg = errData.error || errData.message || errorMsg;
    } catch(e) {}
    
    return new Response(JSON.stringify({ success: false, error: errorMsg }), {
      status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  }

  await addCreditsDirectly(env, parrain_uid, numCredits);
  const updatedUser = await env.DB.prepare("SELECT credits FROM users WHERE uid = ?").bind(parrain_uid).first();

  return new Response(JSON.stringify({ 
    success: true, 
    message: "Points convertis avec succès !", 
    newBalance: updatedUser ? updatedUser.credits : 0
  }), {
    status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" }
  });
}

// ====================================================================
// 6. GÉNÉRATION D'IMAGES ET AUDIO (LYRIA)
// ====================================================================

async function handleImageGeneration(request, user, corsHeaders, env, ctx) {
  const realUid = user.sub; 
  const userEmail = user.email || "email_inconnu"; 
  const currentCredits = await syncAndGetUserCredits(env, realUid, userEmail);
  
  const body = await request.json();
  const action = body.action || "text-to-image"; 
  const modelName = "gemini-3.1-flash-image";

  const responseFormat = body.response_format || {
    type: "image",
    aspect_ratio: body.aspect_ratio || "1:1",
    image_size: body.image_size || "1K"
  };

  const cost = calculateCost(modelName, null);

  if (currentCredits < cost) {
    return new Response(JSON.stringify({ 
      error: "Solde de crédits insuffisant.", 
      required: cost, 
      available: currentCredits 
    }), { status: 402, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const geminiApiKey = env.GEMINI_API_KEY;
  if (!geminiApiKey) {
    return new Response(JSON.stringify({ error: "Service de génération indisponible." }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  let payload = {
    model: modelName,
    response_format: responseFormat
  };

  try {
    switch (action) {
      case "text-to-image":
        payload.input = body.prompt || "A beautiful illustration";
        break;
      case "image-editing":
        payload.input = [
          { type: "text", text: body.prompt || "Edit this image" },
          { type: "image", mime_type: body.mime_type || "image/png", data: validateBase64File(body.image_base64, body.mime_type || "image/png") }
        ];
        break;
      case "video-to-image":
        payload.input = [
          { type: "video", uri: body.video_uri, mime_type: body.mime_type || "video/mp4" },
          { type: "text", text: body.prompt || "Generate poster" }
        ];
        break;
      case "search-grounding":
        payload.input = body.prompt || "Visual weather forecast";
        payload.tools = [{
          type: "google_search",
          search_types: body.search_types || ["web_search", "image_search"]
        }];
        break;
      default:
        return new Response(JSON.stringify({ error: "Action non valide." }), {
          status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
    }

    const upstreamResponse = await fetch("https://generativelanguage.googleapis.com/v1beta/interactions", {
      method: "POST",
      headers: {
        "x-goog-api-key": geminiApiKey,
        "Content-Type": "application/json",
        "Api-Revision": "2026-05-20"
      },
      body: JSON.stringify(payload)
    });

    const data = await upstreamResponse.json();
    if (!upstreamResponse.ok) {
      console.error("[IMAGE_GEN_ERR]", data);
      throw new Error("Génération impossible.");
    }

    ctx.waitUntil(deductCreditsDirectly(env, realUid, cost));
    const updatedCredits = Math.max(0, currentCredits - cost);

    return new Response(JSON.stringify({
      ...data,
      billing: { cost: cost, remainingCredits: updatedCredits }
    }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });

  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
}

async function handleLyriaRequest(request, user, corsHeaders, env, ctx) {
  const realUid = user.sub;
  const userEmail = user.email || "email_inconnu";
  const currentCredits = await syncAndGetUserCredits(env, realUid, userEmail);

  const cost = calculateCost('lyria-3.5', null);

  if (currentCredits < cost) {
    return new Response(JSON.stringify({
      error: "Solde insuffisant.",
      required: cost,
      available: currentCredits
    }), { status: 402, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const apiKey = env.GEMINI_API_KEY;
  if (!apiKey) {
    return new Response(JSON.stringify({ error: "Clé API non configurée." }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const body = await request.json();
  const prompt = body.prompt || "";
  const history = body.history || [];
  const audioData = body.audio_data || null;
  const inputMimeType = body.mime_type || "audio/mp3";
  
  try {
    const result = await callAI(
      apiKey, 
      'lyria-3.5', 
      "Tu es un compositeur musical. Génère la réponse audio MP3.", 
      prompt, 
      history, 
      audioData,
      inputMimeType
    );
    
    ctx.waitUntil(deductCreditsDirectly(env, realUid, cost));
    const updatedCredits = Math.max(0, currentCredits - cost);

    return new Response(JSON.stringify({
      response: result.text,
      audio_base64: result.audioData,
      audio_mime_type: result.audioMimeType,
      model_used: 'lyria-3.5',
      rawData: result.rawData,
      billing: { cost: cost, remainingCredits: updatedCredits }
    }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
}

// ====================================================================
// 7. DICTIONNAIRE DE PROMPTS & CHAT GEMINI
// ====================================================================

const PROMPTS_IA = {
  enseignant: (texte) => `Voici la demande à traiter : ${texte}\n\nDirectives de formatage :\n- Pour les tableaux, utilise le format Markdown standard.\n- Pour les schémas géométriques ou organigrammes, génère un bloc de code au format mermaid.\n- Pour les expressions mathématiques, utilise LaTeX avec $ et $$.`,
  quiz: (texte) => `Génère un quiz de exactement 10 questions à choix multiples basé sur le texte suivant. Réponds exclusivement sous la forme d'un tableau JSON structuré ainsi : {"question": "...", "options": ["A", "B", "C", "D"], "answerIndex": 0, "explanation": "..."}. Texte : ${texte}`,
  traduction: (texte, lang) => `Traduis ce texte en ${lang} : ${texte}`,
  rh_analysis: (cvText, country, currentDate) => `Agis en tant qu'expert en recrutement pour le pays : ${country}. Date du jour : ${currentDate}.\n1. Analyse le CV.\n2. Trouve des offres actuelles.\nTermine par la balise exacte 'JOBS_LIST:' suivie de :\n[SCORE]% | [Poste] | [Entreprise] | [Date] | [URL]\nCV :\n${cvText}`,
  rh_improve: (cvText) => `Améliore le CV suivant et renvoie UNIQUEMENT le contenu final au format Markdown :\n${cvText}`,
  rh_gen_cv: (d) => `Rédige un CV complet et professionnel au format Markdown pour : Nom=${d.nom}, Diplôme=${d.diplome}, Poste=${d.poste}.`,
  rh_gen_lettre: (d) => `Rédige une lettre de motivation pour le poste de ${d.poste} chez ${d.entreprise}.`,
  extract_multimodal: () => `Analyse ce document visuellement. Extrais tout le texte, formate les maths en LaTeX et les schémas en Mermaid.`,
  valider_doc_rh: (texte) => `Analyse ce document. Réponds uniquement par VALID_CV ou INVALID_DOCUMENT.\nDocument :\n${texte}`,
  assistant: (texte) => `Tu es une IA généraliste, utile et bienveillante. Réponds à la demande :\n${texte}`,
  valider_archive: (texte, type) => type === 'payant' ? `Vérifie si ce texte est un sujet d'examen. OUI -> 'CONFORME' + résumé. Sinon 'NON_CONFORME'. Texte :\n${texte}` : `Vérifie si sujet d'examen. OUI -> 'CONFORME', sinon 'NON_CONFORME'. Texte :\n${texte}`
};

async function handleGeminiChatAndBalance(request, env, user, corsHeaders, ctx) {
  const realUid = user.sub; 
  const userEmail = user.email || "email_inconnu"; 
  const currentCredits = await syncAndGetUserCredits(env, realUid, userEmail);
  const body = await request.json(); 

  if (body.action === "get_balance") { 
    return new Response(JSON.stringify({ remainingCredits: currentCredits }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  if (currentCredits <= 0) { 
    return new Response(JSON.stringify({ error: "Solde de crédits insuffisant." }), { status: 402, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const geminiApiKey = env.GEMINI_API_KEY;
  if (!geminiApiKey) {
    return new Response(JSON.stringify({ error: "Clé IA non configurée." }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  let finalPromptText = body.prompt || ""; 
  let webResultsContext = "";
  const todayDate = new Date().toLocaleDateString("fr-FR");

  switch(body.action) {
    case "enseignant": finalPromptText = PROMPTS_IA.enseignant(body.text); break;
    case "quiz": finalPromptText = PROMPTS_IA.quiz(body.text); break;
    case "traduction": finalPromptText = PROMPTS_IA.traduction(body.text, body.lang); break;
    case "assistant": finalPromptText = PROMPTS_IA.assistant(body.text); break;
    case "rh_analysis":
      finalPromptText = PROMPTS_IA.rh_analysis(body.cvText, body.country, todayDate);
      if (env.SERPER_API_KEY && body.country) {
        try {
          const serperRes = await fetch("https://google.serper.dev/search", {
            method: "POST", headers: { "X-API-KEY": env.SERPER_API_KEY, "Content-Type": "application/json" },
            body: JSON.stringify({ q: `offres d'emploi ${body.country}`, num: 5 })
          });
          const serperData = await serperRes.json();
          if (serperData.organic) {
            webResultsContext = "\n\nExemples d'offres :\n" + serperData.organic.map(item => `- ${item.title}: ${item.link}`).join("\n");
          }
        } catch (err) {
          console.error("[SERPER_SEARCH_ERR]", err);
        }
      }
      finalPromptText += `${webResultsContext}\nTermine par 'JOBS_LIST:' suivie du format requis.`;
      break;
    case "rh_improve": finalPromptText = PROMPTS_IA.rh_improve(body.cvText); break;
    case "rh_gen_cv": finalPromptText = PROMPTS_IA.rh_gen_cv(body); break;
    case "rh_gen_lettre": finalPromptText = PROMPTS_IA.rh_gen_lettre(body); break;
    case "valider_doc_rh": finalPromptText = PROMPTS_IA.valider_doc_rh(body.text); break;
    case "valider_archive": finalPromptText = PROMPTS_IA.valider_archive(body.text, body.type); break;
    case "extract_multimodal": finalPromptText = PROMPTS_IA.extract_multimodal(); break;
  }

  const rawHistory = Array.isArray(body.history) ? body.history.slice(-10) : [];
  const formattedHistory = [];
  for (const msg of rawHistory) {
    const role = (msg.role === 'model' || msg.role === 'assistant') ? 'model' : 'user';
    const content = msg.content || msg.text || '';
    if (content) {
      formattedHistory.push({
        role: role,
        parts: [{ text: content }]
      });
    }
  }

  const userParts = [{ text: finalPromptText }];

  if (body.fileData && body.mimeType) {
    try {
      const validatedBase64 = validateBase64File(body.fileData, body.mimeType);
      userParts.push({
        inline_data: {
          mime_type: body.mimeType,
          data: validatedBase64
        }
      });
    } catch (valErr) {
      return new Response(JSON.stringify({ error: valErr.message }), { 
        status: 400, 
        headers: { ...corsHeaders, "Content-Type": "application/json" } 
      });
    }
  }

  const contents = [...formattedHistory, { role: 'user', parts: userParts }];
  const model = "gemini-3.6-flash";
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${geminiApiKey}`;

  const payload = {
    contents: contents,
    generationConfig: { 
      temperature: 0.2
    }
  };

  try {
    const aiResponse = await fetch(url, { 
      method: "POST", 
      headers: { "Content-Type": "application/json" }, 
      body: JSON.stringify(payload) 
    });

    const aiData = await aiResponse.json(); 
    if (!aiResponse.ok || aiData.error) {
      console.error("[GEMINI_CHAT_ERROR]", aiData);
      throw new Error("L'IA n'a pas pu générer de réponse.");
    }

    const cost = calculateCost(model, aiData);

    ctx.waitUntil(deductCreditsDirectly(env, realUid, cost));
    const updatedCredits = Math.max(0, currentCredits - cost);

    const candidate = aiData.candidates?.[0];
    let iaTextContent = "";
    if (candidate?.content?.parts) {
      for (const part of candidate.content.parts) {
        if (part.text) iaTextContent += part.text;
      }
    }

    return new Response(JSON.stringify({ 
      response: iaTextContent, 
      billing: { cost: cost, remainingCredits: updatedCredits },
      raw: aiData
    }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });

  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), { 
      status: 500, 
      headers: { ...corsHeaders, "Content-Type": "application/json" } 
    });
  }
}

// ====================================================================
// 8. ROUTEUR ET EXPORT DU WORKER
// ====================================================================

export default {
  async fetch(request, env, ctx) {
    const corsHeaders = getCorsHeaders(request);
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    if (request.method === "GET" && url.pathname === "/setup-db") {
      await setupDatabase(env);
      return new Response("Base de données initialisée", { headers: corsHeaders });
    }

    if (request.method === "GET" && url.pathname === "/") { 
      return new Response("Worker API Sécurisé Orange Money & Gemini Prêt", { headers: corsHeaders }); 
    }

    if (request.method === "POST" && url.pathname === "/notif") {
      return await handleOrangeWebhook(request, env, corsHeaders);
    }

    if (request.method === "GET" && url.pathname.startsWith("/check-payment/")) {
      try {
        const orderIdToken = url.pathname.split("/").pop();

        const dbRecord = await env.DB.prepare("SELECT * FROM payments WHERE token = ?").bind(orderIdToken).first();
        if (!dbRecord) {
          return new Response(JSON.stringify({ status: "pending", message: "Transaction introuvable." }), {
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }

        if (dbRecord.status === "pending") {
          const rawParsed = JSON.parse(dbRecord.raw_data);
          const accessToken = await getOrangeAccessToken(env);

          const statusResponse = await fetch(ORANGE_STATUS_API, {
            method: "POST",
            headers: {
              "Authorization": `Bearer ${accessToken}`,
              "Accept": "application/json",
              "Content-Type": "application/json"
            },
            body: JSON.stringify({
              order_id: dbRecord.token,
              amount: rawParsed.amount,
              pay_token: rawParsed.pay_token
            })
          });
          
          const remoteData = await statusResponse.json();

          const isPaid = remoteData.status === "SUCCESS";
          const isFailed = remoteData.status === "FAILED" || remoteData.status === "EXPIRED";
          
          if (isPaid && dbRecord.status !== 'completed') {
             const finalInvoiceUrl = remoteData.txnid || dbRecord.invoice_url || "paye_api";
             
             const updateResult = await env.DB.prepare(
               "UPDATE payments SET status = 'completed', invoice_url = ? WHERE token = ? AND status = 'pending'"
             ).bind(finalInvoiceUrl, orderIdToken).run();
               
             if (updateResult.success && updateResult.meta && updateResult.meta.changes > 0) {
                 await addCreditsDirectly(env, rawParsed.userId, rawParsed.creditsRequested);
             }
             dbRecord.status = "completed";
          } else if (isFailed && dbRecord.status !== 'failed') {
             await env.DB.prepare("UPDATE payments SET status = 'failed' WHERE token = ?").bind(orderIdToken).run();
             dbRecord.status = "failed";
          }
        }

        const isPaidFinal = dbRecord.status === "completed";

        return new Response(JSON.stringify({
          success: isPaidFinal,
          status: isPaidFinal ? "completed" : (dbRecord.status || "pending"),
          invoice_url: dbRecord.invoice_url
        }), {
            headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      } catch (e) {
        console.error("[CHECK_PAYMENT_ERROR]", e);
        return new Response(JSON.stringify({ error: "Erreur de vérification du paiement." }), { status: 500, headers: corsHeaders });
      }
    }

    // Protection des routes via JWT Firebase
    try {
      if (!env.FIREBASE_PROJECT_ID) {
          throw new Error("Configuration d'authentification manquante.");
      }

      const authResult = await verifyFirebaseToken(request, env.FIREBASE_PROJECT_ID);
      if (authResult.error) {
        return new Response(JSON.stringify({ error: authResult.error }), {
          status: 401,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }

      if (request.method === "POST" && url.pathname === "/pay-credits") {
        return await handlePayCredits(request, authResult.user, corsHeaders, env);
      }

      if (request.method === "POST" && url.pathname === "/convert-points") {
        return await handleConvertPoints(request, authResult.user, corsHeaders, env);
      }

      if (request.method === "POST" && url.pathname === "/web-search") {
        return await handleWebSearch(request, authResult.user, corsHeaders, env);
      }

      if (request.method === "POST" && url.pathname === "/generate-image") {
        return await handleImageGeneration(request, authResult.user, corsHeaders, env, ctx);
      }

      if (request.method === "POST" && url.pathname === "/chat") { 
        return await handleGeminiChatAndBalance(request, env, authResult.user, corsHeaders, ctx);
      }

      if (request.method === "POST" && url.pathname === "/generate-music") {
        return await handleLyriaRequest(request, authResult.user, corsHeaders, env, ctx);
      }

      if (request.method === "POST" && url.pathname === "/") { 
        return await handleGeminiChatAndBalance(request, env, authResult.user, corsHeaders, ctx);
      }

    } catch (error) {
      console.error("[ROUTE_ERROR]", error);
      return new Response(JSON.stringify({ error: "Erreur serveur interne." }), {
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    return new Response(JSON.stringify({ error: "Route introuvable" }), {
      status: 404,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  }
};
