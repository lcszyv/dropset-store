require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const { MercadoPagoConfig, Preference } = require('mercadopago');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// CORS manual para garantir
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    if (req.method === 'OPTIONS') return res.sendStatus(200);
    next();
});

// Configurações
const mpClient = new MercadoPagoConfig({ accessToken: process.env.MERCADO_PAGO_ACCESS_TOKEN });
const preference = new Preference(mpClient);
const pool = new Pool({ connectionString: process.env.SUPABASE_DATABASE_URL });
const JWT_SECRET = process.env.JWT_SECRET || 'dropset_secret_key_2025';

// Conectar ao banco
async function iniciar() {
    try {
        await pool.connect();
        console.log('✅ Banco conectado!');
    } catch (err) {
        console.error('❌ Erro no banco:', err.message);
    }
}

// Middleware de autenticação
function verificarToken(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ erro: 'Token não fornecido' });
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ erro: 'Token inválido' });
        req.usuario = decoded;
        next();
    });
}

// ================= ROTAS =================

// Status
app.get('/api/status', (req, res) => {
    res.json({ status: '✅ Servidor rodando!', banco: 'Conectado' });
});

// Listar produtos
app.get('/api/produtos', async (req, res) => {
    try {
        const resultado = await pool.query('SELECT * FROM produtos ORDER BY id DESC');
        res.json(resultado.rows);
    } catch (erro) {
        res.status(500).json({ erro: erro.message });
    }
});

// Criar produto
app.post('/api/produtos', async (req, res) => {
    try {
        const { nome, preco, descricao, categoria, imagem_url, estoque } = req.body;
        const resultado = await pool.query(
            `INSERT INTO produtos (nome, preco, descricao, categoria, imagem_url, estoque) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
            [nome, preco, descricao, categoria, imagem_url, estoque]
        );
        res.status(201).json(resultado.rows[0]);
    } catch (erro) {
        res.status(500).json({ erro: erro.message });
    }
});

// ✅ REGISTRO DE USUÁRIO (CADASTRO) - ROTA PRINCIPAL
app.post('/api/registro', async (req, res) => {
    console.log('📥 Recebido registro:', req.body.email); // Debug
    
    try {
        const { nome, email, senha, telefone } = req.body;
        
        if (!nome || !email || !senha) {
            return res.status(400).json({ erro: 'Nome, email e senha são obrigatórios' });
        }
        
        // Verificar email duplicado
        const emailExistente = await pool.query('SELECT id FROM usuarios WHERE email = $1', [email]);
        if (emailExistente.rows.length > 0) {
            return res.status(409).json({ erro: 'Este email já está cadastrado' });
        }
        
        // Criptografar senha
        const saltRounds = 10;
        const senhaHash = await bcrypt.hash(senha, saltRounds);
        
        // Inserir no banco
        const resultado = await pool.query(
            `INSERT INTO usuarios (nome, email, senha_hash, telefone) VALUES ($1, $2, $3, $4) RETURNING id, nome, email, telefone, created_at`,
            [nome, email, senhaHash, telefone || null]
        );
        
        const usuario = resultado.rows[0];
        
        // Gerar token JWT
        const token = jwt.sign({ id: usuario.id, email: usuario.email }, JWT_SECRET, { expiresIn: '7d' });
        
        console.log(`✅ Usuário registrado: ${usuario.email}`);
        res.status(201).json({ mensagem: 'Usuário registrado!', usuario, token });
        
    } catch (erro) {
        console.error('❌ ERRO NO REGISTRO:', erro.message);
        res.status(500).json({ erro: 'Erro interno ao registrar usuário' });
    }
});

// Login
app.post('/api/login', async (req, res) => {
    try {
        const { email, senha } = req.body;
        if (!email || !senha) return res.status(400).json({ erro: 'Email e senha obrigatórios' });
        
        const resultado = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
        if (resultado.rows.length === 0) return res.status(401).json({ erro: 'Email ou senha inválidos' });
        
        const usuario = resultado.rows[0];
        const senhaValida = await bcrypt.compare(senha, usuario.senha_hash);
        if (!senhaValida) return res.status(401).json({ erro: 'Email ou senha inválidos' });
        
        const token = jwt.sign({ id: usuario.id, email: usuario.email }, JWT_SECRET, { expiresIn: '7d' });
        
        res.json({ mensagem: 'Login realizado!', usuario: { id: usuario.id, nome: usuario.nome, email: usuario.email, telefone: usuario.telefone }, token });
    } catch (erro) {
        console.error('❌ Erro no login:', erro.message);
        res.status(500).json({ erro: 'Erro ao fazer login' });
    }
});

// Perfil (protegido)
app.get('/api/perfil', verificarToken, async (req, res) => {
    try {
        const resultado = await pool.query('SELECT id, nome, email, telefone, created_at FROM usuarios WHERE id = $1', [req.usuario.id]);
        if (resultado.rows.length === 0) return res.status(404).json({ erro: 'Usuário não encontrado' });
        res.json(resultado.rows[0]);
    } catch (erro) {
        res.status(500).json({ erro: 'Erro ao buscar perfil' });
    }
});

// Pagamento - Carrinho Múltiplo
app.post('/api/pagamento-multiplo', async (req, res) => {
    try {
        const { cart, usuario } = req.body;
        const items = cart.map(item => ({
            title: item.nome.substring(0, 100),
            unit_price: Number(item.preco),
            quantity: Number(item.quantidade),
            currency_id: 'BRL'
        }));

        const body = {
            items: items,
            back_urls: { success: 'http://localhost:3000', failure: 'http://localhost:3000', pending: 'http://localhost:3000' },
            ...(usuario && { payer: { name: usuario.nome?.split(' ')[0], surname: usuario.nome?.split(' ').slice(1).join(' '), email: usuario.email } })
        };

        const result = await preference.create({ body });
        res.json({ link: result.init_point });
    } catch (error) {
        console.error('❌ ERRO MP:', error.message);
        res.status(500).json({ erro: error.message });
    }
});
// Salvar pedido no banco
app.post('/api/pedidos', verificarToken, async (req, res) => {
    try {
        const { carrinho, total, pagamento_id } = req.body;
        
        const resultado = await pool.query(
            `INSERT INTO pedidos (usuario_id, itens, total, status, pagamento_id) 
             VALUES ($1, $2, $3, 'pendente', $4) RETURNING id, created_at`,
            [req.usuario.id, JSON.stringify(carrinho), total, pagamento_id || null]
        );
        
        res.status(201).json({ mensagem: 'Pedido salvo!', pedido_id: resultado.rows[0].id });
    } catch (erro) {
        console.error('❌ Erro ao salvar pedido:', erro.message);
        res.status(500).json({ erro: 'Erro ao salvar pedido' });
    }
});

// Buscar pedidos do usuário
app.get('/api/meus-pedidos', verificarToken, async (req, res) => {
    try {
        const resultado = await pool.query(
            `SELECT id, itens, total, status, pagamento_id, created_at 
             FROM pedidos 
             WHERE usuario_id = $1 
             ORDER BY created_at DESC`,
            [req.usuario.id]
        );
        res.json(resultado.rows);
    } catch (erro) {
        console.error('❌ Erro ao buscar pedidos:', erro.message);
        res.status(500).json({ erro: 'Erro ao buscar pedidos' });
    }
});
// Iniciar servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Servidor DropSet ativo na porta ${PORT}`);
    console.log(`🔐 Rotas disponíveis: /api/registro, /api/login, /api/produtos, /api/pagamento-multiplo`);
});

iniciar();