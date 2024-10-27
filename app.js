const express = require("express");
const app = express();
const { engine } = require("express-handlebars");
const { createStarList } = require("./controllers/handlebarsHelper");
const { createPagination } = require("express-handlebars-paginate");
const session = require("express-session");
app.use(express.static(__dirname + "/public"));

app.engine(
    "hbs",
    engine({
        layoutsDir: __dirname + "/views/layouts",
        partialsDir: __dirname + "/views/partials",
        defaultLayout: "layout", // default layout is "layout" in "views/layouts" folder. You can change it as per your requirement.  // default layout is "main" in "views/layouts" folder. You can change it as per your requirement.  // default layout is "main" in "views/layouts" folder. You can change it as per your requirement.  // default layout is "
        extname: "hbs",
        runtimeOptions: {
            allowProtoPropertiesByDefault: true,
        },
        helpers: {
            createStarList,
            createPagination,
        },
    }),
);
app.set("view engine", "hbs");
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(
    session({
        secret: "S3cret",
        resave: false,
        saveUninitialized: true,
        cookie: {
            httpOnly: true,
            maxAge: 60000 * 1,
        }, // Set secure to false for development environment to allow cookie access from client-side (http) requests.  // Set secure to false for development environment to allow cookie access from client-side (http) requests.  // Set secure to false for development environment to allow cookie access from client-side (http) requests.  // Set secure to false for development environment to allow cookie access from client-side (http) requests.  // Set secure to false for development environment to allow cookie access from client-side (http) requests.  // Set secure to false for development environment to allow cookie access from client-side (http) requests.  // Set secure to false for development environment to allow cookie access from client-side (http) requests.  // Set secure to false for development environment to allow cookie access from client-side (http)
    }),
);
app.use((req, res, next) => {
    let Cart = require("./controllers/cart");
    req.session.cart = new Cart(req.session.cart ? req.session.cart : {});
    res.locals.quantity = req.session.cart.quantity;
    next();
});
app.use("/", require("./routes/indexRouter"));
app.use("/user", require("./routes/userRouter"));
app.use("/products", require("./routes/productsRouter"));

app.use((req, res, next) => {
    res.status(404).render("error", { message: "File not found" });
});
app.use((error, req, res, next) => {
    console.error(error);
    res.status(500).render("error", { message: "Internet Server Error" });
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
