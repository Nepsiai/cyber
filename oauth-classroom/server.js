const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const crypto = require('crypto');
const path = require('path');
const os = require('os');
const QRCode = require('qrcode');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });
const PORT = 3000;

app.use(express.static(path.join(__dirname, 'public')));

// ── Get LAN IP ────────────────────────────────────────────────────
function getLanIP() {
  const nets = os.networkInterfaces();
  for (const name of Object.keys(nets)) {
    for (const net of nets[name]) {
      if (net.family === 'IPv4' && !net.internal) return net.address;
    }
  }
  return 'localhost';
}

// ── QR Code endpoint ──────────────────────────────────────────────
app.get('/qr', async (req, res) => {
  const ip = getLanIP();
  const url = `http://${ip}:${PORT}`;
  const qrDataUrl = await QRCode.toDataURL(url, { width: 400, margin: 2, color: { dark: '#000', light: '#fff' } });
  res.send(`<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>QR - OAuth 2.0 Classroom</title>
<style>
  body{margin:0;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;background:#0f0f1a;color:#e0e0e0;font-family:system-ui,sans-serif;text-align:center;padding:20px}
  h1{font-size:2rem;margin-bottom:5px}h1 span{color:#6c63ff}
  p{color:#888;margin-bottom:30px;font-size:1.1rem}
  img{border-radius:16px;box-shadow:0 20px 60px rgba(108,99,255,0.3);background:white;padding:16px}
  .url{margin-top:24px;background:#1a1a2e;padding:14px 28px;border-radius:12px;font-size:1.3rem;font-weight:700;color:#00e676;font-family:monospace;letter-spacing:1px}
  .hint{color:#666;margin-top:16px;font-size:0.9rem}
</style></head><body>
  <h1>🔐 OAuth 2.0 <span>Classroom</span></h1>
  <p>Escanea el QR con tu celular para unirte</p>
  <img src="${qrDataUrl}" alt="QR Code" width="300" height="300">
  <div class="url">${url}</div>
  <div class="hint">Asegurate de estar en la misma red WiFi</div>
</body></html>`);
});

// ── State ──────────────────────────────────────────────────────────
const state = {
  students: new Map(),        // socketId → { name, role, team, score }
  teacher: null,              // socketId
  phase: 'lobby',             // lobby | roleAssign | simulation | quiz | scoreboard
  simulation: null,           // current simulation state
  teams: new Map(),           // teamName → { members[], score }
  quizAnswers: new Map(),     // socketId → answer
  currentQuestion: null,
  questionIndex: 0,
  flowSteps: [],
  currentFlowStep: 0,
};

// ── OAuth 2.0 Roles ───────────────────────────────────────────────
const ROLES = ['Usuario (Resource Owner)', 'Cliente (App)', 'Authorization Server', 'Resource Server'];
const TEAM_COLORS = ['#e74c3c', '#3498db', '#2ecc71', '#f39c12', '#9b59b6', '#1abc9c', '#e67e22', '#34495e'];

// ── Quiz questions ────────────────────────────────────────────────
const QUIZ = [
  {
    q: '¿Quién es el "Resource Owner" en OAuth 2.0?',
    options: ['El servidor de autorización', 'El usuario dueño de los datos', 'La aplicación cliente', 'El navegador web'],
    correct: 1,
    explanation: 'El Resource Owner es el usuario que posee los datos y otorga permiso a la aplicación para acceder a ellos.'
  },
  {
    q: '¿Qué es un "Authorization Code"?',
    options: ['La contraseña del usuario', 'Un código temporal que se intercambia por un Access Token', 'El token de acceso final', 'Una cookie del navegador'],
    correct: 1,
    explanation: 'El Authorization Code es un código temporal y de un solo uso que el cliente intercambia por un Access Token.'
  },
  {
    q: '¿Por qué el Access Token NO se envía directamente al navegador en el Authorization Code Flow?',
    options: ['Porque el navegador no soporta tokens', 'Por seguridad: el token viaja solo por el backend (canal seguro)', 'Porque el token es muy grande', 'No hay razón técnica'],
    correct: 1,
    explanation: 'El Access Token viaja por el "back channel" (servidor a servidor) para evitar que quede expuesto en el navegador o URL.'
  },
  {
    q: '¿Qué contiene típicamente un Access Token JWT?',
    options: ['Solo el nombre del usuario', 'Claims como issuer, expiration, scopes y subject', 'La contraseña encriptada', 'La IP del servidor'],
    correct: 1,
    explanation: 'Un JWT contiene claims como iss (emisor), exp (expiración), sub (sujeto), scope (permisos) entre otros.'
  },
  {
    q: '¿Cuál es la función del Refresh Token?',
    options: ['Refrescar la página web', 'Obtener un nuevo Access Token sin pedir login al usuario', 'Cambiar la contraseña del usuario', 'Actualizar los permisos del servidor'],
    correct: 1,
    explanation: 'El Refresh Token permite obtener nuevos Access Tokens cuando el actual expira, sin requerir que el usuario inicie sesión de nuevo.'
  },
  {
    q: '¿Qué es un "Scope" en OAuth 2.0?',
    options: ['El rango de IP permitido', 'Los permisos específicos que la app solicita', 'El tiempo de vida del token', 'La URL de callback'],
    correct: 1,
    explanation: 'Los Scopes definen qué permisos específicos solicita la aplicación (ej: read:profile, write:posts).'
  },
  {
    q: '¿Qué es la "Redirect URI" (callback URL)?',
    options: ['La URL del login de Google', 'La URL donde el Auth Server envía al usuario después de autorizar', 'La URL del API protegido', 'La URL de la base de datos'],
    correct: 1,
    explanation: 'La Redirect URI es la URL registrada donde el Authorization Server redirige al usuario tras autorizar, incluyendo el authorization code.'
  },
  {
    q: '¿Qué ataque previene el parámetro "state" en OAuth 2.0?',
    options: ['SQL Injection', 'CSRF (Cross-Site Request Forgery)', 'XSS (Cross-Site Scripting)', 'DDoS'],
    correct: 1,
    explanation: 'El parámetro "state" es un valor aleatorio que previene ataques CSRF verificando que la respuesta corresponde a la solicitud original.'
  },
  {
    q: '¿Cuál es la diferencia entre OAuth 2.0 y OpenID Connect (OIDC)?',
    options: ['Son exactamente lo mismo', 'OAuth es para autorización, OIDC agrega autenticación (identidad)', 'OIDC reemplazó completamente a OAuth', 'OAuth es más nuevo que OIDC'],
    correct: 1,
    explanation: 'OAuth 2.0 es un protocolo de autorización. OpenID Connect es una capa sobre OAuth que agrega autenticación e información de identidad del usuario (ID Token).'
  },
  {
    q: '¿Qué tipo de Grant/Flow es más seguro para aplicaciones web con backend?',
    options: ['Implicit Grant', 'Authorization Code + PKCE', 'Client Credentials', 'Resource Owner Password'],
    correct: 1,
    explanation: 'Authorization Code con PKCE es el flow más seguro para apps web con backend, ya que el token nunca se expone en el frontend y PKCE previene ataques de intercepción.'
  },
];

// ── Flow Steps for simulation ─────────────────────────────────────
const FLOW_STEPS = [
  {
    step: 1,
    title: '🧑 Usuario quiere acceder a un recurso',
    from: 'Usuario',
    to: 'Cliente',
    description: 'El usuario hace clic en "Iniciar sesión con Google" en la aplicación.',
    technical: 'El usuario interactúa con la UI del cliente.',
    data: null,
    animation: 'user-to-client'
  },
  {
    step: 2,
    title: '📱 Cliente redirige al Auth Server',
    from: 'Cliente',
    to: 'Auth Server',
    description: 'La aplicación redirige al usuario al servidor de autorización con los parámetros necesarios.',
    technical: 'GET /authorize?response_type=code&client_id=APP123&redirect_uri=https://app.com/callback&scope=read:profile&state=xyz789',
    data: { response_type: 'code', client_id: 'APP123', redirect_uri: 'https://app.com/callback', scope: 'read:profile', state: 'xyz789' },
    animation: 'client-to-auth'
  },
  {
    step: 3,
    title: '🔐 Auth Server muestra pantalla de login',
    from: 'Auth Server',
    to: 'Usuario',
    description: 'El servidor de autorización muestra la pantalla de inicio de sesión y consentimiento al usuario.',
    technical: 'El Auth Server valida client_id, redirect_uri, y muestra la pantalla de consentimiento con los scopes solicitados.',
    data: { prompt: '¿Permitir que APP123 acceda a tu perfil?' },
    animation: 'auth-to-user'
  },
  {
    step: 4,
    title: '✅ Usuario autoriza el acceso',
    from: 'Usuario',
    to: 'Auth Server',
    description: 'El usuario ingresa sus credenciales y acepta los permisos solicitados.',
    technical: 'POST /authorize (credentials + consent=allow)',
    data: { consent: 'allow', scopes_approved: ['read:profile'] },
    animation: 'user-to-auth'
  },
  {
    step: 5,
    title: '🎟️ Auth Server genera Authorization Code',
    from: 'Auth Server',
    to: 'Cliente',
    description: 'El Auth Server redirige al usuario de vuelta a la app con un código temporal.',
    technical: null, // generated dynamically
    data: null,
    animation: 'auth-to-client'
  },
  {
    step: 6,
    title: '🔄 Cliente intercambia código por Access Token',
    from: 'Cliente',
    to: 'Auth Server',
    description: 'El backend de la app envía el código + sus credenciales secretas al Auth Server (back channel).',
    technical: null,
    data: null,
    animation: 'client-to-auth-back'
  },
  {
    step: 7,
    title: '🪙 Auth Server emite Access Token',
    from: 'Auth Server',
    to: 'Cliente',
    description: 'El Auth Server valida todo y devuelve el Access Token (y opcionalmente un Refresh Token).',
    technical: null,
    data: null,
    animation: 'auth-to-client-back'
  },
  {
    step: 8,
    title: '📦 Cliente accede al recurso protegido',
    from: 'Cliente',
    to: 'Resource Server',
    description: 'La app usa el Access Token para pedir datos del usuario al API protegido.',
    technical: null,
    data: null,
    animation: 'client-to-resource'
  },
  {
    step: 9,
    title: '📋 Resource Server valida y responde',
    from: 'Resource Server',
    to: 'Cliente',
    description: 'El Resource Server valida el token y devuelve los datos protegidos.',
    technical: null,
    data: null,
    animation: 'resource-to-client'
  },
  {
    step: 10,
    title: '🎉 Usuario ve sus datos',
    from: 'Cliente',
    to: 'Usuario',
    description: 'La aplicación muestra al usuario sus datos obtenidos del recurso protegido.',
    technical: 'La app renderiza los datos del perfil del usuario.',
    data: { profile: { name: 'Estudiante', email: 'estudiante@universidad.edu' } },
    animation: 'client-to-user'
  }
];

function generateCode() {
  return crypto.randomBytes(16).toString('hex');
}

function generateToken() {
  return 'eyJhbGciOiJSUzI1NiJ9.' + Buffer.from(JSON.stringify({
    iss: 'https://auth.example.com',
    sub: 'user_' + crypto.randomBytes(4).toString('hex'),
    aud: 'APP123',
    exp: Math.floor(Date.now() / 1000) + 3600,
    scope: 'read:profile',
    iat: Math.floor(Date.now() / 1000)
  })).toString('base64url') + '.' + crypto.randomBytes(32).toString('base64url');
}

function broadcast() {
  const studentsArr = [];
  state.students.forEach((s, id) => studentsArr.push({ ...s, id }));
  const teamsArr = [];
  state.teams.forEach((t, name) => teamsArr.push({ name, ...t }));

  io.emit('state', {
    phase: state.phase,
    students: studentsArr,
    teams: teamsArr,
    currentFlowStep: state.currentFlowStep,
    flowSteps: FLOW_STEPS,
    currentQuestion: state.currentQuestion,
    questionIndex: state.questionIndex,
    totalQuestions: QUIZ.length,
  });
}

// ── Socket handlers ───────────────────────────────────────────────
io.on('connection', (socket) => {
  console.log(`Connected: ${socket.id}`);

  socket.on('join', ({ name, isTeacher }) => {
    if (isTeacher) {
      state.teacher = socket.id;
      socket.emit('role', 'teacher');
    } else {
      state.students.set(socket.id, { name, role: null, team: null, score: 0 });
      socket.emit('role', 'student');
    }
    broadcast();
  });

  socket.on('teacher:startSimulation', () => {
    if (socket.id !== state.teacher) return;
    state.phase = 'simulation';
    state.currentFlowStep = 0;

    // Generate dynamic data for steps
    const authCode = generateCode();
    const accessToken = generateToken();
    const refreshToken = 'rt_' + crypto.randomBytes(20).toString('hex');

    FLOW_STEPS[4].technical = `302 Redirect → https://app.com/callback?code=${authCode.slice(0,16)}&state=xyz789`;
    FLOW_STEPS[4].data = { authorization_code: authCode.slice(0, 16), state: 'xyz789' };

    FLOW_STEPS[5].technical = `POST /token\nContent-Type: application/x-www-form-urlencoded\n\ngrant_type=authorization_code&code=${authCode.slice(0,16)}&redirect_uri=https://app.com/callback&client_id=APP123&client_secret=SECRET456`;
    FLOW_STEPS[5].data = { grant_type: 'authorization_code', code: authCode.slice(0, 16), client_id: 'APP123', client_secret: 'SECRET456' };

    FLOW_STEPS[6].technical = `200 OK\n{\n  "access_token": "${accessToken.slice(0, 40)}...",\n  "token_type": "Bearer",\n  "expires_in": 3600,\n  "refresh_token": "${refreshToken.slice(0, 20)}..."\n}`;
    FLOW_STEPS[6].data = { access_token: accessToken.slice(0, 40) + '...', token_type: 'Bearer', expires_in: 3600, refresh_token: refreshToken.slice(0, 20) + '...' };

    FLOW_STEPS[7].technical = `GET /api/profile\nAuthorization: Bearer ${accessToken.slice(0, 30)}...`;
    FLOW_STEPS[7].data = { authorization: `Bearer ${accessToken.slice(0, 30)}...` };

    FLOW_STEPS[8].technical = `200 OK\n{\n  "id": "user_abc123",\n  "name": "Estudiante",\n  "email": "estudiante@universidad.edu",\n  "avatar": "https://example.com/avatar.jpg"\n}`;
    FLOW_STEPS[8].data = { id: 'user_abc123', name: 'Estudiante', email: 'estudiante@universidad.edu' };

    broadcast();
  });

  socket.on('teacher:nextStep', () => {
    if (socket.id !== state.teacher) return;
    if (state.currentFlowStep < FLOW_STEPS.length - 1) {
      state.currentFlowStep++;
      io.emit('flowStep', { step: state.currentFlowStep, data: FLOW_STEPS[state.currentFlowStep] });
      broadcast();
    }
  });

  socket.on('teacher:prevStep', () => {
    if (socket.id !== state.teacher) return;
    if (state.currentFlowStep > 0) {
      state.currentFlowStep--;
      broadcast();
    }
  });

  socket.on('teacher:startQuiz', () => {
    if (socket.id !== state.teacher) return;
    state.phase = 'quiz';
    state.questionIndex = 0;
    state.quizAnswers.clear();
    state.currentQuestion = QUIZ[0];
    // Reset scores
    state.students.forEach(s => s.score = 0);
    broadcast();
  });

  socket.on('teacher:nextQuestion', () => {
    if (socket.id !== state.teacher) return;
    // Show answer for current question first
    io.emit('quizReveal', {
      correct: QUIZ[state.questionIndex].correct,
      explanation: QUIZ[state.questionIndex].explanation,
      stats: getAnswerStats()
    });
  });

  socket.on('teacher:advanceQuestion', () => {
    if (socket.id !== state.teacher) return;
    state.questionIndex++;
    state.quizAnswers.clear();
    if (state.questionIndex < QUIZ.length) {
      state.currentQuestion = QUIZ[state.questionIndex];
      broadcast();
    } else {
      state.phase = 'scoreboard';
      broadcast();
    }
  });

  socket.on('teacher:backToLobby', () => {
    if (socket.id !== state.teacher) return;
    state.phase = 'lobby';
    broadcast();
  });

  socket.on('student:answer', ({ answer }) => {
    if (!state.students.has(socket.id)) return;
    if (state.quizAnswers.has(socket.id)) return; // already answered

    state.quizAnswers.set(socket.id, answer);
    const student = state.students.get(socket.id);

    if (answer === QUIZ[state.questionIndex].correct) {
      // Faster answers get more points
      const answeredCount = state.quizAnswers.size;
      const bonus = Math.max(0, 10 - answeredCount);
      student.score += 10 + bonus;
    }

    // Notify teacher of answer count
    io.to(state.teacher).emit('answerCount', { count: state.quizAnswers.size, total: state.students.size });
    socket.emit('answerAck', { received: true });
  });

  socket.on('student:interact', ({ action }) => {
    // Students can trigger visual effects during simulation
    io.emit('studentAction', { name: state.students.get(socket.id)?.name, action });
  });

  socket.on('disconnect', () => {
    if (socket.id === state.teacher) {
      state.teacher = null;
    }
    state.students.delete(socket.id);
    broadcast();
  });
});

function getAnswerStats() {
  const stats = [0, 0, 0, 0];
  state.quizAnswers.forEach(a => { if (a >= 0 && a < 4) stats[a]++; });
  return stats;
}

// ── Start ─────────────────────────────────────────────────────────
server.listen(PORT, '0.0.0.0', () => {
  console.log('\n╔══════════════════════════════════════════════════╗');
  console.log('║     🎓 OAuth 2.0 Classroom - Servidor Activo    ║');
  console.log('╠══════════════════════════════════════════════════╣');
  console.log(`║  Local:   http://localhost:${PORT}                 ║`);

  const nets = os.networkInterfaces();
  for (const name of Object.keys(nets)) {
    for (const net of nets[name]) {
      if (net.family === 'IPv4' && !net.internal) {
        const ip = net.address;
        const pad = ' '.repeat(Math.max(0, 35 - ip.length - 5));
        console.log(`║  Red:     http://${ip}:${PORT}${pad}║`);
      }
    }
  }

  console.log('╠══════════════════════════════════════════════════╣');
  console.log('║  Profesor: agrega ?teacher al URL                ║');
  console.log('║  Alumnos:  abren el URL directamente             ║');
  console.log('╚══════════════════════════════════════════════════╝\n');
});
