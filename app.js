const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const { check, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');

const app = express();
app.use(bodyParser.json());

const port = process.env.PORT || 3000;
app.listen(port, () => {
    console.log(`Servidor rodando na porta ${port}`);
});

// Configurações de Segurança
const JWT_SECRET = process.env.JWT_SECRET || 'suaChaveSecretaParaJWTQueNinguemVaiAdivinhar_ParaDesenvolvimento'; // ATENÇÃO: Em produção, use variável de ambiente e chave forte!
const JWT_EXPIRATION_TIME = '1h';
const SALT_ROUNDS = 10;

// Mock de Dados de Usuários (senhas hasheadas)
const users = [{
    "username": "user",
    "password": bcrypt.hashSync("123456", SALT_ROUNDS),
    "id": 123,
    "email": "user@dominio.com",
    "perfil": "user"
}, {
    "username": "admin",
    "password": bcrypt.hashSync("123456789", SALT_ROUNDS),
    "id": 124,
    "email": "admin@dominio.com",
    "perfil": "admin"
}, {
    "username": "colab",
    "password": bcrypt.hashSync("123", SALT_ROUNDS),
    "id": 125,
    "email": "colab@dominio.com",
    "perfil": "user"
}, ];

// Simulação de Banco de Dados para Contratos (SQLite em memória)
const db = new sqlite3.Database(':memory:');
db.serialize(() => {
    db.run(`CREATE TABLE contracts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        empresa TEXT,
        data_inicio TEXT,
        valor REAL
    )`);
    db.run("INSERT INTO contracts (empresa, data_inicio, valor) VALUES ('Empresa A', '2023-01-01', 1000.50)");
    db.run("INSERT INTO contracts (empresa, data_inicio, valor) VALUES ('Empresa B', '2024-03-15', 2500.75)");
    db.run("INSERT INTO contracts (empresa, data_inicio, valor) VALUES ('Empresa A', '2024-05-20', 1200.00)");
    console.log("Banco de dados de contratos populado para demonstração.");
});

// Middleware de Autenticação JWT
function authenticateJWT(req, res, next) {
    const authHeader = req.headers.authorization;

    if (authHeader) {
        const token = authHeader.split(' ')[1];

        jwt.verify(token, JWT_SECRET, (err, user) => {
            if (err) {
                return res.status(403).json({
                    message: 'Token inválido ou expirado.'
                });
            }
            req.user = user;
            next();
        });
    } else {
        res.status(401).json({
            message: 'Token de autenticação ausente.'
        });
    }
}

// Middleware de Autorização (Controle de Acesso Baseado em Perfil)
function authorizeRoles(allowedRoles) {
    return (req, res, next) => {
        if (!req.user || !req.user.perfil) {
            return res.status(403).json({
                message: 'Acesso negado. Informações de perfil ausentes.'
            });
        }

        if (allowedRoles.includes(req.user.perfil)) {
            next();
        } else {
            res.status(403).json({
                message: 'Acesso negado. Você não tem permissão para acessar este recurso.'
            });
        }
    };
}

// Função de login: Verifica credenciais e gera um JWT.
function doLogin(credentials) {
    const user = users.find(item => item.username === credentials?.username);

    if (!user || !bcrypt.compareSync(credentials?.password, user.password)) {
        return null;
    }
    return user;
}

// Função para buscar contratos no banco de dados. Protegida contra SQL Injection.
function getContractsSafe(empresa, inicio, callback) {
    // Uso de Prepared Statements para prevenir SQL Injection.
    const query = `SELECT * FROM contracts WHERE empresa = ? AND data_inicio = ?`;
    db.all(query, [empresa, inicio], (err, rows) => {
        if (err) {
            console.error("Erro na busca de contratos:", err.message);
            callback(err, null);
        } else {
            callback(null, rows);
        }
    });
}

// Endpoint de Login: Gera o JWT após autenticação.
app.post('/api/auth/login', [
    check('username').notEmpty().withMessage('Username é obrigatório'),
    check('password').notEmpty().withMessage('Password é obrigatório')
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { username, password } = req.body;
    const userData = doLogin({ username, password });

    if (userData) {
        const token = jwt.sign({
            id: userData.id,
            username: userData.username,
            perfil: userData.perfil
        }, JWT_SECRET, {
            expiresIn: JWT_EXPIRATION_TIME
        });
        res.json({
            message: 'Login bem-sucedido',
            token: token
        });
    } else {
        res.status(401).json({
            message: 'Usuário ou senha incorretos.'
        });
    }
});

// Endpoint para recuperação dos dados de TODOS os usuários. Restrito a 'admin'.
app.get('/api/users', authenticateJWT, authorizeRoles(['admin']), (req, res) => {
    res.status(200).json({
        data: users.map(user => {
            const { password, ...userWithoutPassword } = user;
            return userWithoutPassword;
        })
    });
});

// NOVO Endpoint: Recupera os dados do usuário LOGADO. Acessível por qualquer autenticado.
app.get('/api/me', authenticateJWT, (req, res) => {
    const currentUser = users.find(u => u.id === req.user.id);

    if (currentUser) {
        const {
            password,
            ...userWithoutPassword
        } = currentUser;
        res.status(200).json({
            data: userWithoutPassword
        });
    } else {
        res.status(404).json({
            message: 'Dados do usuário logado não encontrados.'
        });
    }
});

// Endpoint para recuperação dos contratos existentes. Restrito a 'admin'.
app.get('/api/contracts/:empresa/:inicio', [
    authenticateJWT,
    authorizeRoles(['admin']),
    check('empresa').notEmpty().withMessage('O nome da empresa é obrigatório na URL.'),
    check('inicio').isISO8601().withMessage('A data de início deve ser uma data ISO 8601 válida (YYYY-MM-DD).')
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const {
        empresa,
        inicio
    } = req.params;

    getContractsSafe(empresa, inicio, (err, result) => {
        if (err) {
            console.error('Erro interno ao buscar contratos:', err.message);
            return res.status(500).json({
                message: 'Erro interno do servidor ao buscar contratos.'
            });
        }

        if (result && result.length > 0) {
            res.status(200).json({
                data: result
            });
        } else {
            res.status(404).json({
                data: 'Dados de contratos não encontrados.'
            });
        }
    });
});

// Garante que a conexão com o banco de dados em memória seja fechada ao sair do processo.
process.on('SIGINT', () => {
    db.close((err) => {
        if (err) console.error(err.message);
        console.log('Conexão com o banco de dados em memória fechada.');
        process.exit(0);
    });
});