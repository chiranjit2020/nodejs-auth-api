import jwt from "jsonwebtoken";

export const protect = (req, res, next) => {
    const token = req.headers.authorization?.split(" ")[1];
    if(!token) return res.status(401).send({ error: "Unauthorized"});

    try{
        const decode = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
        req.user = decode.id;
        next();
    }catch{
        return res.status(401).send({error: "Invalid token"});
    }
};
