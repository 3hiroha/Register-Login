const express = require("express");
const mysql = require("mysql2");
const bodyParser = require("body-parser");
const app = express();
const port = 3000;
const bcrypt = require("bcrypt");
const { check, validationResult } = require("express-validator");
var jwt =require("jsonwebtoken");

// Parse various different custom JSON types as JSON
const cookieParser = require("cookie-parser");
app.use(bodyParser.json({ type: "application/json" }));
app.use(cookieParser());


// initialize sql & connection
const connection = mysql.createConnection({
	host: "server2.bsthun.com",
	port: "6105",
	user: "lab_iagoa",
	password: "yeQPdqrbuGjKaSDP",
	database: "lab_todo02_i5gqqp",
});

connection.connect(() => {
	console.log("Database is connected");
});

app.use(bodyParser.json({ type: "application/json" }));

// get endpoint
app.get("/", (req, res) => {
  res.send("Hello World!");
});

// endpoint login (Assignment)

app.post("/basic/login", async (req,res) => {
    const username = req.body.username;
    const password = req.body.password;

    connection.query("SELECT * FROM users where username = ?", [username], async (err,rows) => {
        if (err) {
			res.json({
				success: false,
				data: null,
				error: err.message,
			});
		} else {
            numRows = rows.length;
			if (numRows == 0){
				res.json({
					success: false,
					message:"this credential does not exist",
				});
			} 
            const isMatch = await bcrypt.compare(password, rows[0].hashed_password);
            if (!isMatch) {
                res.json({
					success: false,
					message:"the password is incorrect",
				});
            } else {
                const token = jwt.sign(
                    {
                        userId : rows[0].id,
                    },
                    "ZJGX1QL7ri6BGJWj3t",
                    { expiresIn : "1h"}
                );
                res.cookie("user", token);
                res.json({
					success: true,
					message:"the password is correct",
                    user: rows[0],
				});
            }
        }
	})
})
// Check login by cookies (Assignment Cookies)  5/10/2023
    app.get("/basic/check",  (req,res) => {
        // const token = req.cookies.user;
        var decoded = jwt.verify(req.cookies.user, "ZJGX1QL7ri6BGJWj3t");
        console.log(decoded);
        if(!decoded){
            res.json({
                success : false,
                message : "User is not loggged in",
            })
        }else{
            res.json({
                success : true,
                message : "User is logged in with Id: "+decoded.userId,
            })
        }
    })
//  get todo all endpoint --- display only todo owned by the signed user
    app.get("/basic/todo/all", async (req,res) => {
        
        var decoded = jwt.verify(req.cookies.user, "ZJGX1QL7ri6BGJWj3t");
        console.log(decoded.userId);
        connection.query("SELECT * FROM items WHERE owner_id=?", [decoded.userId], (err,rows) => {
            if(err){
                res.json({
                    Success : false,
                    Data : null,
                    error : err.message
                })
            }else{
                res.json({
                    Success : true,
                    Data : rows,
                    error : null
                })

            }
        })
    })
    
// endpoint register (Assignment)

app.post("/basic/register",
        check("password").notEmpty().withMessage("password cannot be empty")
        .isLength({min:8}).withMessage("password must be at least 8 characters")
        .matches(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])[0-9a-zA-Z]{8,}$/)
        .withMessage("password must have at least 1 digits of number, uppercase and lowercase"), 
    async (req,res) => {
    const username = req.body.username;
    const password = req.body.password;
    const errors = validationResult(req);

    if(!errors.isEmpty()) {
        return res.json({ 
            errors: errors.array() 
        });

    }
    const hashpassword = await bcrypt.hash(password, 10);
    connection.query(
        "INSERT INTO users (username, password, hashed_password, created_at, updated_at) VALUES (?, ?, ?, ? ,?)",
		[username, password, hashpassword, new Date(), new Date()], (err,rows) => {
            if(err) {
                res.json({
                    success: false,
                    data: null,
                    error: err.message
                });

            }else{
                console.log(rows);
                if(rows){
                    res.json({
                        success: true,
                        data: 
                            {
                                message: "register success"
                            }
                    })
                }
            }
        }

    )

    
})



app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});