import express from "express"; // --
import mongoose from "mongoose"; // --
import bcrypt from "bcrypt"; // serve para criptografar senha --
import jwt from "jsonwebtoken"; // criar e validar tokens JWT --
import dotenv from "dotenv"; // Ambiente com arquivo .env --
import User from "./models/usuarioModel.js";


dotenv.config(); // Carregar as variaveis de ambiente do arquivo .ENV

const app = express();


app.use(express.json());

// rota aberta
app.get("/", (req, res) => {
  res.status(200).json({ msg: "Bem vindo a nossa API! " });
});

// Rota privada
app.get("user/:id", checkToken, async (req, res) => {
  const id = req.params.id;

  const user = await User.findById(id, "-password"); // Busca no banco o user sem a senha

  if (!user) {
    return res.status(404).json({ msg: "Usuario não encontrado!" });
  }

  res.status(200).json({ user }); // retorna os dados do user encontrado
});

function checkToken(req, res, next) {
  const authHeader = req.headers["Autorization"];
  const token = authHeader && authHeader.splint(" ")[1];

  if (!token) return res.status(401).json({ msg: "Acesso negado! " });

  try {
    const secret = process.env.SECRET;

    jwt.verify(token, secret);

    next();
  } catch (err) {
    res.status(400).json({ msg: "O token é inválido"});
  }
}

// Criação de usuario
app.post("/auth/register", async (req, res) => {
  const { name, email, password, confirmpassword } = req.body;

  if (!name) {
    return res.status(422).json({ msg: "O nome é obrigatório" });
  }

  if (!email) {
    return res.status(422).json({ msg: "O email é obrigatório" });
  }

  if (!password) {
    return res.status(422).json({ msg: "A senha é obrigatório" });
  }

  if (password != confirmpassword) {
    return res
      .status(422)
      .json({ msg: "A senha e a confirmação precisao ser iguais!" });
  }


  const userExists = await User.findOne({ email: email });

  if (userExists) {
    return res.status(422).json({ msg: "Por Favor, utilize outro email!" });
  }

  const salt = await bcrypt.genSalt(12);  // Gera um salt para criptografar a senha 
  const passwordHash = await bcrypt.hash(password, salt); // cria um hash da senha usando o salt 

  const user = new User({
    name,
    email,
    passwordHash,
  });

  try {
    await user.save();

    res.status(201).json({ msg: "Usuario criado com sucesso!" });
  } catch (error) {
    res.status(500).json({ msg: error });
  }

});

app.post("/auth/login", async (req, res) => {
    const { email, password } = req.body;

    if (!email) {
        return res.status(422).json({ msg: "O email deve ser informado! "});
    }

    if (!password) {
        return res.status(422).json({ msg: "A senha deve ser informada! "});
    }

    const user = await user.findOne({ email: email}); // Busca o usuario no banco

    if (!user) {
        return res.status(404).json({ msg: "Usuario não encontrado!"});
    }

    const checkPassword = await bcrypt.compare(password, user.password);

    if (!checkPassword) {
        return res.status(422).json({ msg: "Senha inválida, tente novamente. "});
    }

    // Fazer um secret para evitar invasões
    try {
        const secret = process.env.SECRET;

        const token = jwt.sign(
            {
                id: user._id // cria o token JWT contendo o id do usuario
            },
            secret
        );

        res.status(200).json({ msg: "Autenticação realizada com sucesso!", token});
    } catch (error) {
        res.status(500).json({ msg: error }); // Somente se não gerar o token
    }
});

// Credenciais
const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASS;

mongoose
  .connect(
    `mongodb+srv://${dbUser}:${dbPassword}@projeto-api.veajh.mongodb.net/?retryWrites=true&w=majority&appName=PROJETO-API`
  )
  .then(() => {
    app.listen(3000);
    console.log("Conectou ao Banco!");
  })
  .catch((err) => console.log(err));

// DB_USER=adminY
// DB_PASS=Br1fNvUtyVlMjrLT
// SECRET=?BATATAFRITA$!?

// colocar no .env