const risks = [
  {
    id: 'a01',
    code: 'A01: Broken Access Control',
    name: 'Control de acceso roto',
    summary: 'Un usuario sin privilegios logra ver o modificar información que no le corresponde.',
    description:
      'Aquí puedes probar cómo una ruta protegida debería bloquear la consulta si el rol no coincide con el recurso.',
    lesson:
      'El problema aparece cuando la aplicación confía solo en la interfaz y no valida permisos en el backend.',
    points: [
      'Cambia el rol y observa que la versión vulnerable deja entrar por error.',
      'La versión segura revisa si el usuario tiene permiso antes de mostrar el recurso.',
      'La validación debe vivir en el servidor, no solo en el botón o la pantalla.',
    ],
    fields: [
      {
        type: 'select',
        key: 'role',
        label: 'Rol del usuario',
        options: ['visitor', 'editor', 'admin'],
        defaultValue: 'visitor',
      },
      {
        type: 'select',
        key: 'resource',
        label: 'Recurso a abrir',
        options: ['dashboard', 'reports', 'users'],
        defaultValue: 'users',
      },
    ],
    run(state) {
      const permissions = {
        visitor: ['dashboard'],
        editor: ['dashboard', 'reports'],
        admin: ['dashboard', 'reports', 'users'],
      };
      const allowed = permissions[state.role].includes(state.resource);
      return [
        `Vulnerable: la interfaz no bloquea el acceso a ${state.resource}.`,
        `Seguro: ${allowed ? 'permiso concedido' : 'acceso denegado'} para el rol ${state.role}.`,
        allowed
          ? 'El backend confirma que el usuario puede ver el recurso.'
          : 'El backend corta la petición aunque el usuario intente abrirla.',
      ].join('\n');
    },
  },
  {
    id: 'a02',
    code: 'A02: Cryptographic Failures',
    name: 'Fallos criptográficos',
    summary: 'Datos sensibles se exponen sin cifrado o con un almacenamiento débil.',
    description:
      'Compara una tarjeta que muestra secretos en texto plano con otra que los oculta o protege correctamente.',
    lesson:
      'No basta con esconder un campo en la vista: si el dato viaja o se guarda sin protección, sigue siendo vulnerable.',
    points: [
      'Observa cómo un secreto visible en texto plano es fácil de copiar.',
      'La versión segura enmascara o protege la información sensible.',
      'La defensa real usa cifrado y gestión correcta de claves.',
    ],
    fields: [
      {
        type: 'text',
        key: 'secret',
        label: 'Dato sensible',
        defaultValue: 'mi-contrasena-super-secreta',
      },
    ],
    run(state) {
      const masked = state.secret.length > 6 ? `${state.secret.slice(0, 2)}${'*'.repeat(Math.max(4, state.secret.length - 4))}${state.secret.slice(-2)}` : '****';
      return [
        `Vulnerable: el dato aparece como \"${state.secret}\".`,
        `Seguro: se muestra como \"${masked}\" y se almacena cifrado.`,
        'Si alguien accede a la pantalla o a la base de datos, el impacto baja de forma importante.',
      ].join('\n');
    },
  },
  {
    id: 'a03',
    code: 'A03: Injection',
    name: 'Inyección SQL',
    summary: 'Una consulta armada con concatenación permite que una entrada cambie la lógica de búsqueda.',
    description:
      'Escribe un usuario de prueba y compara la consulta insegura con una versión parametrizada que trata la entrada como dato.',
    lesson:
      'Este ejemplo es local y educativo: simula una base de datos para que veas cómo la entrada afecta al filtro.',
    points: [
      'La cadena vulnerable concatena el texto tal cual llega.',
      'La versión segura usa parámetros y no interpreta la entrada como SQL.',
      'El bloqueo real ocurre antes de tocar la base de datos.',
    ],
    fields: [
      {
        type: 'text',
        key: 'username',
        label: 'Usuario',
        defaultValue: "admin' OR '1'='1",
      },
      {
        type: 'text',
        key: 'password',
        label: 'Contraseña',
        defaultValue: '123456',
      },
    ],
    run(state) {
      const users = [
        { username: 'admin', password: 'admin123', role: 'admin' },
        { username: 'ana', password: 'clave123', role: 'user' },
      ];
      const rawQuery = `SELECT * FROM users WHERE username = '${state.username}' AND password = '${state.password}'`;
      const attackerPattern = /'\s*or\s*'1'\s*=\s*'1/i;
      const vulnerableMatch = attackerPattern.test(`${state.username} ${state.password}`);
      const safeMatch = users.find((item) => item.username === state.username && item.password === state.password);
      return [
        `Consulta vulnerable:\n${rawQuery}`,
        vulnerableMatch
          ? 'Vulnerable: la condición se altera y el filtro queda abierto para devolver más registros.'
          : 'Vulnerable: la búsqueda solo funciona con valores exactos, pero sigue siendo insegura.',
        `Seguro: consulta parametrizada -> SELECT * FROM users WHERE username = ? AND password = ?`,
        safeMatch
          ? `Resultado seguro: acceso de ${safeMatch.role}.`
          : 'Resultado seguro: credenciales inválidas.',
      ].join('\n\n');
    },
  },
  {
    id: 'a04',
    code: 'A04: Insecure Design',
    name: 'Diseño inseguro',
    summary: 'La aplicación no contempla límites, flujos o controles para resistir abuso.',
    description:
      'Prueba un login sin límite de intentos y compáralo con una versión con bloqueo temporal y freno de abuso.',
    lesson:
      'Un diseño seguro prevé el ataque antes de que ocurra, no solo reacciona cuando ya pasó.',
    points: [
      'La ausencia de límites facilita el ataque por fuerza bruta.',
      'Un contador y una pausa temporal reducen el abuso.',
      'El diseño seguro considera amenazas desde el inicio.',
    ],
    fields: [
      {
        type: 'number',
        key: 'attempts',
        label: 'Intentos de login',
        defaultValue: 6,
      },
      {
        type: 'select',
        key: 'mfa',
        label: 'MFA',
        options: ['off', 'on'],
        defaultValue: 'off',
      },
    ],
    run(state) {
      const blocked = Number(state.attempts) >= 5;
      return [
        `Vulnerable: se permiten ${state.attempts} intentos sin pausa ni bloqueo.`,
        `Seguro: ${blocked ? 'la cuenta entra en bloqueo temporal' : 'la cuenta sigue protegida y el umbral no se alcanza'}.`,
        state.mfa === 'on'
          ? 'MFA activo: aunque la contraseña se adivine, falta un segundo factor.'
          : 'Sin MFA, el login depende solo de la contraseña.',
      ].join('\n');
    },
  },
  {
    id: 'a05',
    code: 'A05: Security Misconfiguration',
    name: 'Mala configuración de seguridad',
    summary: 'Opciones como debug, listas de directorios o permisos amplios quedan expuestas.',
    description:
      'Activa y desactiva configuraciones típicas para ver cómo un entorno puede revelar demasiado.',
    lesson:
      'La configuración por defecto no siempre es segura. Quitar debug y cerrar puertas innecesarias es parte del trabajo.',
    points: [
      'El modo debug puede exponer detalles internos.',
      'Las cabeceras y permisos deben reducirse al mínimo.',
      'Lo que no se necesita, se apaga o se restringe.',
    ],
    fields: [
      {
        type: 'select',
        key: 'debug',
        label: 'Modo debug',
        options: ['off', 'on'],
        defaultValue: 'on',
      },
      {
        type: 'select',
        key: 'listing',
        label: 'Listado de directorios',
        options: ['off', 'on'],
        defaultValue: 'on',
      },
    ],
    run(state) {
      return [
        `Vulnerable: debug ${state.debug === 'on' ? 'activo' : 'apagado'} y listado ${state.listing === 'on' ? 'habilitado' : 'deshabilitado'}.`,
        `Seguro: debug apagado, listado de directorios bloqueado y mensajes de error genéricos.`,
        'Menos información visible significa menos pistas para un atacante.',
      ].join('\n');
    },
  },
  {
    id: 'a06',
    code: 'A06: Vulnerable and Outdated Components',
    name: 'Componentes vulnerables u obsoletos',
    summary: 'Usar librerías viejas deja abiertas fallas ya conocidas y publicadas.',
    description:
      'Simula una revisión de versión para ver cómo una dependencia desactualizada cambia el resultado.',
    lesson:
      'Mantener dependencias al día reduce la superficie de ataque y evita fallos ya corregidos por terceros.',
    points: [
      'Las versiones antiguas suelen tener CVEs conocidas.',
      'Un inventario de dependencias ayuda a detectar riesgos.',
      'Actualizar a tiempo es una defensa concreta y medible.',
    ],
    fields: [
      {
        type: 'text',
        key: 'component',
        label: 'Componente',
        defaultValue: 'lib-ui',
      },
      {
        type: 'number',
        key: 'version',
        label: 'Versión',
        defaultValue: 2,
      },
    ],
    run(state) {
      const safeVersion = 5;
      const vulnerable = Number(state.version) < safeVersion;
      return [
        `Componente: ${state.component} v${state.version}.`,
        vulnerable
          ? 'Vulnerable: esta versión tiene fallos conocidos y necesita actualización.'
          : 'Seguro: la versión está dentro del rango recomendado.',
        `Recomendación: revisar el changelog y aplicar parches antes de exponerlo en producción.`,
      ].join('\n');
    },
  },
  {
    id: 'a07',
    code: 'A07: Identification and Authentication Failures',
    name: 'Fallos de identificación y autenticación',
    summary: 'Contraseñas débiles, sesiones mal manejadas o falta de MFA facilitan el acceso no autorizado.',
    description:
      'Prueba la fuerza de una contraseña y mira cómo cambia el resultado cuando el sistema exige un segundo factor.',
    lesson:
      'La autenticación no termina en pedir una clave; también importa la fortaleza, el bloqueo y la sesión.',
    points: [
      'Las claves cortas o comunes son muy fáciles de adivinar.',
      'Los bloqueos por intentos limitan la fuerza bruta.',
      'MFA agrega una capa extra si la contraseña falla.',
    ],
    fields: [
      {
        type: 'text',
        key: 'password',
        label: 'Contraseña',
        defaultValue: '123456',
      },
      {
        type: 'select',
        key: 'mfa',
        label: 'MFA',
        options: ['off', 'on'],
        defaultValue: 'off',
      },
    ],
    run(state) {
      const weak = state.password.length < 8 || /123456|password|admin/i.test(state.password);
      return [
        `Vulnerable: la contraseña \"${state.password}\" ${weak ? 'es débil' : 'todavía puede mejorarse'}.`,
        `Seguro: el sistema exige política fuerte${state.mfa === 'on' ? ' y segundo factor' : ''}.`,
        weak ? 'Con una clave así, el acceso puede caer rápido ante un ataque automatizado.' : 'Una contraseña robusta eleva bastante la dificultad.',
      ].join('\n');
    },
  },
  {
    id: 'a08',
    code: 'A08: Software and Data Integrity Failures',
    name: 'Fallos de integridad de software y datos',
    summary: 'Actualizaciones o datos modificados sin validación pueden introducir código alterado.',
    description:
      'Cambia el estado de firma para ver cómo una entrega sin verificación puede ser interceptada.',
    lesson:
      'Si no validas origen e integridad, no sabes si el paquete que llega es el que salió del proveedor.',
    points: [
      'Las firmas y hashes protegen la cadena de entrega.',
      'Los artefactos sin verificación se vuelven un riesgo.',
      'La integridad importa tanto como la confidencialidad.',
    ],
    fields: [
      {
        type: 'select',
        key: 'signature',
        label: 'Firma digital',
        options: ['valid', 'tampered'],
        defaultValue: 'tampered',
      },
    ],
    run(state) {
      const safe = state.signature === 'valid';
      return [
        `Vulnerable: artefacto ${state.signature === 'tampered' ? 'alterado' : 'sin verificar'}.`,
        safe ? 'Seguro: la firma coincide y la actualización puede aplicarse.' : 'Bloqueado: la firma no coincide y el paquete se rechaza.',
        'La verificación debe ocurrir antes de ejecutar el software o confiar en los datos.',
      ].join('\n');
    },
  },
  {
    id: 'a09',
    code: 'A09: Security Logging and Monitoring Failures',
    name: 'Fallas de logging y monitoreo',
    summary: 'Si no registras eventos importantes, un incidente puede pasar desapercibido.',
    description:
      'Genera acciones sospechosas y mira cómo cambia el resultado cuando existe trazabilidad.',
    lesson:
      'Sin logs útiles, detectar un incidente es tarde y reconstruir la causa es más difícil.',
    points: [
      'Registrar intentos fallidos ayuda a detectar abuso.',
      'Las alertas aceleran la respuesta.',
      'Monitorear no evita el ataque, pero reduce el tiempo de exposición.',
    ],
    fields: [
      {
        type: 'select',
        key: 'logging',
        label: 'Registro activo',
        options: ['off', 'on'],
        defaultValue: 'off',
      },
      {
        type: 'number',
        key: 'events',
        label: 'Eventos sospechosos',
        defaultValue: 3,
      },
    ],
    run(state) {
      const count = Number(state.events);
      return [
        `Vulnerable: ${state.logging === 'on' ? 'sí' : 'no'} hay registros y se ven ${count} eventos sospechosos.`,
        state.logging === 'on'
          ? 'Seguro: los eventos quedan trazados y se puede alertar al equipo.'
          : 'Sin logs, el incidente puede quedar invisible para el operador.',
        count > 0 ? 'Con alertas, este patrón podría disparar una revisión temprana.' : 'Sin eventos, no hay señal que analizar.'
      ].join('\n');
    },
  },
  {
    id: 'a10',
    code: 'A10: Server-Side Request Forgery',
    name: 'SSRF',
    summary: 'El servidor hace peticiones a recursos internos o peligrosos porque acepta una URL no confiable.',
    description:
      'Escribe una URL de ejemplo y observa cómo la versión segura filtra el destino antes de hacer la solicitud.',
    lesson:
      'Nunca dejes que el servidor consulte cualquier URL sin validar dominio, esquema y red de destino.',
    points: [
      'Un atacante puede apuntar al servidor hacia recursos internos.',
      'Una allowlist limita las URLs permitidas.',
      'La validación debe revisar el esquema y el dominio.',
    ],
    fields: [
      {
        type: 'text',
        key: 'url',
        label: 'URL solicitada',
        defaultValue: 'http://localhost/admin',
      },
    ],
    run(state) {
      const url = String(state.url).trim();
      const safeHost = /^https:\/\/(api\.example\.com|status\.example\.com)\//i.test(url);
      const internal = /localhost|127\.0\.0\.1|10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\./i.test(url);
      return [
        `Vulnerable: el servidor intenta abrir ${url || 'una URL vacía'} sin validación previa.`,
        internal
          ? 'Peligro: la dirección apunta a un recurso interno o sensible.'
          : 'Riesgo moderado: cualquier URL externa sigue siendo una entrada no confiable.',
        safeHost
          ? 'Seguro: la URL está dentro de la allowlist permitida.'
          : 'Seguro: la solicitud se bloquea porque el destino no está permitido.',
      ].join('\n');
    },
  },
];

const stateByRisk = Object.fromEntries(
  risks.map((risk) => [
    risk.id,
    risk.fields.reduce((accumulator, field) => {
      accumulator[field.key] = field.defaultValue;
      return accumulator;
    }, {}),
  ])
);

const riskList = document.querySelector('#riskList');
const riskCode = document.querySelector('#riskCode');
const riskName = document.querySelector('#riskName');
const riskDescription = document.querySelector('#riskDescription');
const lessonText = document.querySelector('#lessonText');
const lessonPoints = document.querySelector('#lessonPoints');
const controlStack = document.querySelector('#controlStack');
const resultOutput = document.querySelector('#resultOutput');
const activeTitle = document.querySelector('#activeTitle');
const activeSummary = document.querySelector('#activeSummary');
const jumpToDemo = document.querySelector('#jumpToDemo');
const resetButton = document.querySelector('#resetButton');

let activeRiskId = risks[2].id;

function createFieldControl(risk, field) {
  const wrapper = document.createElement('div');
  wrapper.className = 'control-card';

  const label = document.createElement('label');
  label.htmlFor = `${risk.id}-${field.key}`;
  label.textContent = field.label;
  wrapper.appendChild(label);

  if (field.type === 'select') {
    const select = document.createElement('select');
    select.id = `${risk.id}-${field.key}`;
    select.dataset.key = field.key;
    for (const option of field.options) {
      const optionNode = document.createElement('option');
      optionNode.value = option;
      optionNode.textContent = option;
      select.appendChild(optionNode);
    }
    select.value = stateByRisk[risk.id][field.key];
    select.addEventListener('change', () => {
      stateByRisk[risk.id][field.key] = select.value;
      updateDemo();
    });
    wrapper.appendChild(select);
    return wrapper;
  }

  if (field.type === 'number') {
    const input = document.createElement('input');
    input.type = 'number';
    input.id = `${risk.id}-${field.key}`;
    input.dataset.key = field.key;
    input.value = stateByRisk[risk.id][field.key];
    input.addEventListener('input', () => {
      stateByRisk[risk.id][field.key] = Number(input.value);
      updateDemo();
    });
    wrapper.appendChild(input);
    return wrapper;
  }

  if (field.type === 'text') {
    const input = document.createElement('input');
    input.type = 'text';
    input.id = `${risk.id}-${field.key}`;
    input.dataset.key = field.key;
    input.value = stateByRisk[risk.id][field.key];
    input.addEventListener('input', () => {
      stateByRisk[risk.id][field.key] = input.value;
      updateDemo();
    });
    wrapper.appendChild(input);
    return wrapper;
  }

  if (field.type === 'textarea') {
    const input = document.createElement('textarea');
    input.id = `${risk.id}-${field.key}`;
    input.dataset.key = field.key;
    input.value = stateByRisk[risk.id][field.key];
    input.addEventListener('input', () => {
      stateByRisk[risk.id][field.key] = input.value;
      updateDemo();
    });
    wrapper.appendChild(input);
    return wrapper;
  }

  return wrapper;
}

function renderRiskList() {
  riskList.innerHTML = '';

  for (const risk of risks) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = `risk-item ${risk.id === activeRiskId ? 'active' : ''}`;
    button.innerHTML = `<strong>${risk.code}</strong><span>${risk.name}</span><span>${risk.summary}</span>`;
    button.addEventListener('click', () => {
      setActiveRisk(risk.id);
      document.querySelector('.demo-panel').scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
    riskList.appendChild(button);
  }
}

function syncRiskListActiveState() {
  riskList.querySelectorAll('.risk-item').forEach((item, index) => {
    item.classList.toggle('active', risks[index].id === activeRiskId);
  });
}

function renderControls(risk) {
  controlStack.innerHTML = '';
  for (const field of risk.fields) {
    controlStack.appendChild(createFieldControl(risk, field));
  }
}

function updateDemo() {
  const risk = risks.find((item) => item.id === activeRiskId);
  const state = stateByRisk[risk.id];

  riskCode.textContent = risk.code;
  riskName.textContent = risk.name;
  riskDescription.textContent = risk.description;
  lessonText.textContent = risk.lesson;
  lessonPoints.innerHTML = risk.points.map((point) => `<li>${point}</li>`).join('');
  activeTitle.textContent = risk.name;
  activeSummary.textContent = risk.summary;
  resultOutput.textContent = risk.run(state);
  syncRiskListActiveState();
}

function setActiveRisk(riskId) {
  activeRiskId = riskId;
  const risk = risks.find((item) => item.id === activeRiskId);
  renderControls(risk);
  updateDemo();
}

jumpToDemo.addEventListener('click', () => {
  document.querySelector('.demo-panel').scrollIntoView({ behavior: 'smooth', block: 'start' });
});

resetButton.addEventListener('click', () => {
  const risk = risks.find((item) => item.id === activeRiskId);
  for (const field of risk.fields) {
    stateByRisk[risk.id][field.key] = field.defaultValue;
  }
  renderControls(risk);
  updateDemo();
});

renderRiskList();
renderControls(risks.find((item) => item.id === activeRiskId));
updateDemo();
