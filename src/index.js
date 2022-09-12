import express from "express";
import cors from "cors";
import { MongoClient } from "mongodb";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import { v4 as uuid } from "uuid";
import dayjs from "dayjs";
import joi from "joi";


dotenv.config();

// express.json()
const server=express();
server.use(express.json());
server.use(cors());

// calling mongo
const mongoClient= new MongoClient(process.env.MONGO_URI);
let db;
mongoClient.connect(()=>{
    db=mongoClient.db('mywallet')
})

// templates
const userRegisterSchema = joi
  .object({
    name: joi.string().empty("").required(),
    email: joi
      .string()
      .email({ minDomainSegments: 2, tlds: { allow: ["com", "net"] } })
      .required(),
    password: joi
      .string()
      .alphanum()
      .required(),
      password_confirm: joi.ref("password"),
  });

const userSigninSchema = joi
  .object({
    email: joi
      .string()
      .email({ minDomainSegments: 2, tlds: { allow: ["com", "net"] } })
      .required(),
    password: joi
      .string()
      .alphanum()
      .required(),
  });

const deposit_withdrawSchema = joi.object({
  value: joi.number().required(),
  title: joi.string().required(),
  type: joi.valid("withdraw").valid("deposit").required(),
});

// get and post APIs
server.post("/signin", async (req, res) => {
    const { email, password } = req.body;
  
    try {
        const validation = userSigninSchema.validate(
            {email,password},
            { abortEarly: false });

        if (validation.error) {
            const err = validation.error.details.map((detail) => detail.message);
            return res.status(422).send({message: "E-mail ou senha em padrão incorreto!"});
        }

        const user = await db.collection("users").findOne({ email });
        const name = user.name;

        const verifiedPassword = bcrypt.compareSync(password, user.password);
    
        if (!verifiedPassword) {
            return res.status(401).send({ message: "E-mail ou senha incorretos!" });
        }
    
        const token = uuid();
    
        await db.collection("login_sessions").insertOne({
            userId: user.id,
            token,
        });
    
        return res.send({ name,token });
    } catch (err) {
        console.error(err);
        return res.sendStatus(500);
    }
  });

server.post("/signup", async (req, res) => {
    const { name, email, password, password_confirm } = req.body;

    const validation = userRegisterSchema.validate(
        {name,email,password,password_confirm},
        { abortEarly: false }
    );
    if (validation.error) {
        const err = validation.error.details.map((detail) => detail.message);
        return res.status(422).send(err);
    }

    try {
        const user = await db.collection("users").findOne({ email });

        if (user) {
        return res.status(409).send({ message: "Este usuário já está cadastrado!" });
        }

        const password_token = bcrypt.hashSync(password, 12);

        await db
        .collection("users")
        .insertOne({ name, email, password: password_token, balance_list: [] });

        return res.sendStatus(201);
    } catch (err) {
        console.error(err);
        return res.sendStatus(500);
    }
});

server.post("/balance", async (req, res) => {
    const token = req.headers.authorization?.replace("Bearer ", "");
    const { value, title, type } = req.body;
    const validation = deposit_withdrawSchema.validate(
        {value, title, type},
        { abortEarly: false });

    if (validation.error) {
        const err = validation.error.details.map((detail) => detail.message);
        return res.status(422).send(err);
    }

    try {
        const logged_user = await db.collection("login_sessions").findOne({ token });

        if (!logged_user) {
            return res.status(401).send({ message: "O usuário não foi encontrado" });
        }

        const user = await db.collection("users").findOne({ id: logged_user.userId });

        const balance_list = user.balance_list;
        let id = balance_list.length + 1;

        const date = dayjs().format("DD/MM");

        const money_amount = Number(value).toFixed(2);

        balance_list.push({ id, date, value: money_amount, title, type });

        await db
        .collection("users")
        .updateOne(
            { id: logged_user.userId },
            { $set: { balance_list: balance_list } }
        );

        return res.sendStatus(201);
    } catch (err) {
        console.error(err);
        return res.sendStatus(500);
    }
});

server.get("/balance", async (req, res) => {
    const token = req.headers.authorization?.replace("Bearer ", "");
    try {
        const logged_user = await db.collection("login_sessions").findOne({ token });

        if (!logged_user) {
        return res.status(401).send({ message: "Usuário não encontrado" });
        }

        const user = await db.collection("users").findOne({ id: logged_user.userId });

        return res.send(user.balance_list);
    } catch (err) {
        console.error(err);
        return res.sendStatus(500);
    }
});


server.listen(5000,function(){console.log('listening on 5000')});

