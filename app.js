"use strict";
var __awaiter =
  (this && this.__awaiter) ||
  function (thisArg, _arguments, P, generator) {
    function adopt(value) {
      return value instanceof P
        ? value
        : new P(function (resolve) {
            resolve(value);
          });
    }
    return new (P || (P = Promise))(function (resolve, reject) {
      function fulfilled(value) {
        try {
          step(generator.next(value));
        } catch (e) {
          reject(e);
        }
      }
      function rejected(value) {
        try {
          step(generator["throw"](value));
        } catch (e) {
          reject(e);
        }
      }
      function step(result) {
        result.done
          ? resolve(result.value)
          : adopt(result.value).then(fulfilled, rejected);
      }
      step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
  };
var __importDefault =
  (this && this.__importDefault) ||
  function (mod) {
    return mod && mod.__esModule ? mod : { default: mod };
  };
Object.defineProperty(exports, "__esModule", { value: true });
const bcrypt_1 = require("bcrypt");
const express_1 = __importDefault(require("express"));
const jsonwebtoken_1 = require("jsonwebtoken");
const promise_1 = __importDefault(require("mysql2/promise"));
const nodemailer_1 = require("nodemailer");
const utils_1 = require("./utils");
const pino_1 = __importDefault(require("pino"));
const logger = (0, pino_1.default)();
const app = (0, express_1.default)();
app.use(express_1.default.json());
const connection = promise_1.default.createPool({
  host: utils_1.env.DB_HOST,
  user: utils_1.env.DB_USER,
  password: utils_1.env.DB_PASSWORD,
  database: utils_1.env.DB_NAME,
  port: utils_1.env.DB_PORT,
});
connection
  .getConnection()
  .then(() => {
    console.log("Connected to the MySQL server.");
  })
  .catch((err) => {
    console.error("Error connecting to the MySQL server:", err);
  });
const transport = (0, nodemailer_1.createTransport)({
  host: "sandbox.smtp.mailtrap.io",
  port: 2525,
  auth: {
    user: "57d3efe575c94e",
    pass: "bb6d2a42e9228f",
  },
});
app.post("/signup", (req, res) =>
  __awaiter(void 0, void 0, void 0, function* () {
    const input = utils_1.signupValidation.parse(req.body);
    const hashedPassword = yield (0, bcrypt_1.hash)(input.password, 10);
    const about = "";
    const profile_image = "";
    const query =
      "INSERT INTO users (name, email, password, about, profile_image) VALUES (?, ?, ?,?,?)";
    try {
      const [result] = yield connection.execute(query, [
        input.name,
        input.email,
        hashedPassword,
        about,
        profile_image,
      ]);
      if (result.affectedRows != 1) {
        res.status(500).send("Error registering user");
      }
      res.status(201).send("User registered successfully");
    } catch (err) {
      console.error(err);
    }
  })
);
app.post("/login", (req, res) =>
  __awaiter(void 0, void 0, void 0, function* () {
    const { email, password } = req.body;
    const query = "SELECT * FROM  users WHERE email = ?";
    try {
      const [results] = yield connection.execute(query, [email]);
      if (results.length === 0) {
        return res.status(404).send("Korisnik nije pronađen");
      }
      const comparison = yield (0, bcrypt_1.compare)(
        password,
        results[0].password
      );
      if (!comparison) {
        return res.status(401).send("Krivo upisan lozinka");
      }
      const secretKey = "your-secret-secret";
      const accessToken = (0, jsonwebtoken_1.sign)(
        { id: results[0].id, email: results[0].email },
        secretKey,
        { expiresIn: "1h" }
      );
      const refreshToken = (0, jsonwebtoken_1.sign)(
        { id: results[0].id, email: results[0].email },
        utils_1.env.REFRESH_SECRET,
        { expiresIn: "7d" }
      );
      res.status(200).send({
        accessToken,
        refreshToken,
        id: results[0].id,
        name: results[0].name,
        email: results[0].email,
        about: results[0].about,
        profile_image: results[0].profile_image,
        role: results[0].role,
      });
    } catch (err) {
      console.error(err);
      return res.status(500).send("Error logging in");
    }
  })
);
app.post("/refresh-token", (req, res) => {
  var _a, _b;
  const { refreshToken } = req.body;
  if (!refreshToken) {
    res.status(401).send("Refresh Token is required");
    return;
  }
  const user = (0, jsonwebtoken_1.verify)(
    refreshToken,
    (_a = process.env.JWT_SECRET) !== null && _a !== void 0 ? _a : ""
  );
  if (typeof user === "string") {
    throw new Error("Decoded user not valid payload");
  }
  const accessToken = (0, jsonwebtoken_1.sign)(
    {
      id: user === null || user === void 0 ? void 0 : user.id,
      email: user === null || user === void 0 ? void 0 : user.email,
    },
    (_b = process.env.JWT_SECRET) !== null && _b !== void 0 ? _b : "",
    { expiresIn: "1h" }
  );
  res.status(200).send({
    accessToken,
  });
});
app.put("/updateUser", (req, res) =>
  __awaiter(void 0, void 0, void 0, function* () {
    const { id, name, email, about } = req.body;
    const query =
      "UPDATE users SET name = ?, email = ?, about = ? WHERE id = ?";
    try {
      const [results] = yield connection.execute(query, [
        name,
        email,
        about,
        id,
      ]);
      if (results) {
        res.status(200).send({ name, email, about });
      } else {
        console.log("Response nije dobar " + results);
      }
    } catch (err) {
      console.log(err);
      res.status(400).send("nešto ne štima");
    }
  })
);
app.get("/users/:id", (req, res) =>
  __awaiter(void 0, void 0, void 0, function* () {
    const userId = parseInt(req.params.id, 10);
    try {
      const [userResult] = yield connection.execute(
        `SELECT 
         id, 
         name, 
         about, 
         email, 
         profile_image 
       FROM users 
       WHERE id = ?`,
        [userId]
      );
      if (userResult.length === 0) {
        return res.status(404).json({ message: "User not found" });
      }
      const [routesResult] = yield connection.execute(
        `SELECT 
         r.id, 
         r.route_name, 
         r.route_description, 
         r.duration, 
         r.distance,
         r.published,
         GROUP_CONCAT(DISTINCT ri.image_url) AS images
       FROM route r
       LEFT JOIN route_images ri ON r.id = ri.route_id
       WHERE r.user_id = ?
       GROUP BY r.id`,
        [userId]
      );
      const routes = routesResult.map((route) => ({
        id: route.id,
        route_name: route.route_name,
        route_description: route.route_description,
        duration: route.duration,
        distance: route.distance,
        published: route.published,
        images: route.images
          ? route.images.split(",").map((url) => ({ image_url: url }))
          : [],
      }));
      const user = userResult[0];
      const userWithRoutes = {
        id: user.id,
        name: user.name,
        about: user.about,
        email: user.email,
        profile_image: user.profile_image,
        routes: routes,
      };
      res.status(200).json(userWithRoutes);
    } catch (err) {
      console.error("Greška u dohvaćanju profila:", err);
      res.status(500).json({ message: "Server error" });
    }
  })
);

app.post("/user/:id/profile-image", (req, res) =>
  __awaiter(void 0, void 0, void 0, function* () {
    const { user_id, profileImageUrl } = req.body;
    const query = "UPDATE users SET profile_image = ? WHERE id = ?";
    try {
      const [result] = yield connection.execute(query, [
        profileImageUrl,
        user_id,
      ]);
      if (result.affectedRows === 0) {
        res.status(404).send("user nije pronađen");
      }
      res.status(200).send("Slika uspješno postavljena !");
    } catch (err) {
      console.log(err);
      res.status(500).send("Ne uspjeh u ažuriranju");
    }
  })
);
app.put("/changePassword", (req, res) =>
  __awaiter(void 0, void 0, void 0, function* () {
    const { id, currentPassword, newPassword } = req.body;
    const query = "SELECT password FROM users WHERE id = ?";
    try {
      const [result] = yield connection.execute(query, [id]);
      if (result.length > 0) {
        const storedPassword = result[0].password;
        const passwordIsValid = yield (0, bcrypt_1.compare)(
          currentPassword,
          storedPassword
        );
        if (passwordIsValid) {
          console.log(passwordIsValid);
          const hashedNewPassword = yield (0, bcrypt_1.hash)(newPassword, 10);
          const updateQuery = "UPDATE users SET password = ? WHERE id = ? ";
          const [updatePassword] = yield connection.execute(updateQuery, [
            hashedNewPassword,
            id,
          ]);
          if (updatePassword.affectedRows > 0) {
            res.status(200).send("Uspješno ažuriranje passworda !");
          } else {
            res.status(400).send("Loš response!");
          }
        } else {
          console.log("Nije dobar password");
          res.status(400).send("Krivo upisana stara šifra!");
        }
      }
    } catch (err) {
      console.log(err);
      res.status(500).send("Greška sa serverom!");
    }
  })
);
app.put("/changeEmail", (req, res) =>
  __awaiter(void 0, void 0, void 0, function* () {
    const { id, currentEmail, newEmail } = req.body;
    const query = "SELECT email FROM users WHERE id = ?";
    try {
      const [result] = yield connection.execute(query, [id]);
      if (result.length > 0) {
        const storedEmail = result[0].email;
        if (storedEmail === currentEmail) {
          console.log("storeEmail " + storedEmail);
          console.log("novi email " + newEmail);
          const updateQuery = "UPDATE users SET email = ? WHERE id = ? ";
          const [updateEmail] = yield connection.execute(updateQuery, [
            newEmail,
            id,
          ]);
          if (updateEmail.affectedRows > 0) {
            res.status(200).send("Uspješno ažuriranje emaila !");
          } else {
            res.status(400).send("Loš response!");
          }
        } else {
          console.log("Nije dobar email");
          res.status(400).send("Email ne odgovara postojećem.");
        }
      }
    } catch (err) {
      console.log(err);
      res.status(500).send("Greška sa serverom!");
    }
  })
);
app.post("/saveRoute", (req, res) =>
  __awaiter(void 0, void 0, void 0, function* () {
    const {
      user_id,
      route_data,
      duration,
      average_speed,
      distance,
      route_name,
      route_description,
      city,
      region,
      country,
    } = req.body;
    const query =
      "INSERT INTO route (user_id, route_data, duration, average_speed, distance, route_name, route_description,city,region,country) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    try {
      const [result] = yield connection.execute(query, [
        user_id,
        route_data,
        duration,
        average_speed,
        distance,
        route_name,
        route_description,
        city,
        region,
        country,
      ]);
      if (result.affectedRows > 0) {
        console.log("Uspješna kreirana ruta !");
        res.status(200).send({ id: result.insertId });
      } else {
        res.status(400).send("Loš request");
      }
    } catch (err) {
      console.log(err);
      res.status(503).send("Server nije upaljen");
    }
  })
);
app.post("/saveImage", (req, res) =>
  __awaiter(void 0, void 0, void 0, function* () {
    const { route_id, image_url, image_geolocation } = req.body;
    if (!route_id || !image_url || !image_geolocation) {
      res.status(400).send("Missing required fields");
      return;
    }
    try {
      const query =
        "INSERT INTO route_images (route_id, image_url, image_geolocation) VALUES (?, ?, ?)";
      const [result] = yield connection.execute(query, [
        route_id,
        image_url,
        image_geolocation,
      ]);
      if (result.affectedRows > 0) {
        res.status(200).send("Uspješno dodana slika/slike!");
      } else {
        res.status(400).send("Niste uspjeli dodati sliku!");
      }
    } catch (err) {
      console.log(err);
      res.status(500).send("Server nije upaljen!");
    }
  })
);
app.get("/getRoutes/:userId", (req, res) =>
  __awaiter(void 0, void 0, void 0, function* () {
    const userId = Number(req.params.userId);
    const query = "SELECT * FROM route WHERE user_id = ? ";
    try {
      const [result] = yield connection.execute(query, [userId]);
      if (result.length > 0) {
        res.status(200).send(result);
      } else {
        res.status(404).send("Nema pronađenih ruta!");
      }
    } catch (err) {
      console.log(err);
    }
  })
);
app.delete("/deleteRoute/:id", (req, res) =>
  __awaiter(void 0, void 0, void 0, function* () {
    const routeId = req.params.id;
    const deleteImagesQuery = "DELETE FROM route_images WHERE route_id = ?";
    const deleteRouteQuery = "DELETE FROM route WHERE id = ?";
    try {
      const [deletedImagesResult] = yield connection.execute(
        deleteImagesQuery,
        [routeId]
      );
      const [deleteRouteResult] = yield connection.execute(deleteRouteQuery, [
        routeId,
      ]);
      if (deleteRouteResult.affectedRows > 0) {
        console.log("Ruta uspješno obrisana!");
        res.status(200).send("Ruta uspješno obrisana.");
      } else {
        console.log("Ruta nije pronađena!");
        res.status(404).send("Ruta nije pronađena!");
      }
    } catch (err) {
      console.log(err);
      res.send(503).send("Server nije u mogućnosti napraviti taj zahtjev!");
    }
  })
);
app.post("/makePrivate/:id", (req, res) =>
  __awaiter(void 0, void 0, void 0, function* () {
    const routeId = req.params.id;
    const query = "UPDATE route SET published = NULL WHERE id = ?";
    try {
      const [result] = yield connection.execute(query, [routeId]);
      if (result.affectedRows > 0) {
        res.status(200).send("Ruta je privatna!");
        console.log("ruta je ažurirana!");
      } else {
        res.status(400).send("Krivi query!");
      }
    } catch (_a) {
      res.status(503).send("Servner ne radi!");
    }
  })
);
app.post("/publishRoute/:id", (req, res) =>
  __awaiter(void 0, void 0, void 0, function* () {
    const routeId = req.params.id;
    const query = "UPDATE route SET published = NOW() WHERE id = ?";
    try {
      const [result] = yield connection.execute(query, [routeId]);
      if (result.affectedRows > 0) {
        res.status(200).send("Ruta je uplodana!");
        console.log("ruta je ažurirana!");
      } else {
        res.status(400).send("Krivi query!");
      }
    } catch (_a) {
      res.status(503).send("Servner ne radi!");
    }
  })
);
app.get("/getRouteDetails/:routeId", (req, res) =>
  __awaiter(void 0, void 0, void 0, function* () {
    const routeId = req.params.routeId;
    const query = "SELECT * FROM route WHERE id = ?";
    try {
      const [result] = yield connection.execute(query, [routeId]);
      console.log("result " + result);
      if (result.length > 0) {
        res.status(200).send(result[0]);
        //  console.log("Uspješno dohvaćanje vrijednosti od rute!");
        //  console.log("uploaded_at iz baze:", result[0].uploaded_at, typeof result[0].uploaded_at);
      } else {
        res.status(400).send("Krivi query");
      }
    } catch (err) {
      console.log(err);
      res.status(503).send("Server ne radi");
    }
  })
);
app.get("/getRouteWithUser/:routeId", (req, res) =>
  __awaiter(void 0, void 0, void 0, function* () {
    const routeId = req.params.routeId;
    const query = `
    SELECT 
      route.*, 
      users.id AS user_id, users.name AS user_name, users.profile_image,
      GROUP_CONCAT(ri.image_url) AS image_urls
    FROM pistracker.route
    JOIN users ON users.id = route.user_id
    LEFT JOIN route_images ri ON route.id = ri.route_id
    WHERE route.id = ?
    GROUP BY route.id;
  `;
    try {
      const [result] = yield connection.execute(query, [routeId]);
      if (result.length > 0) {
        const row = result[0];
        const images = row.image_urls
          ? row.image_urls.split(",").map((url) => ({ image_url: url }))
          : [];
        const response = {
          route: {
            id: row.id,
            route_name: row.route_name,
            route_description: row.route_description,
            distance: row.distance,
            duration: row.duration,
            user_id: row.user_id,
            route_data: row.route_data,
          },
          user: {
            id: row.user_id,
            name: row.user_name,
            profile_image: row.profile_image,
          },
          images: images,
        };
        res.status(200).json(response);
      } else {
        res.status(404).send("Ruta nije pronađena");
      }
    } catch (err) {
      console.error("Greška pri dohvaćanju rute:", err);
      res.status(500).send("Došlo je do pogreške na serveru");
    }
  })
);
app.get("/getRouteImages/:routeId", (req, res) =>
  __awaiter(void 0, void 0, void 0, function* () {
    const routeId = req.params.routeId;
    const query =
      "SELECT image_url,image_geolocation FROM route_images WHERE route_id = ?";
    try {
      const [result] = yield connection.execute(query, [routeId]);
      if (result.length > 0) {
        const formattedImages = result.map((row) => {
          let geolocation = null;
          const parsed = row.image_geolocation;
          if (Array.isArray(parsed) && parsed.length === 2) {
            geolocation = {
              lat: parsed[1],
              lng: parsed[0],
            };
          }
          return {
            image_url: row.image_url,
            image_geolocation: geolocation,
          };
        });
        res.status(200).json(formattedImages);
      } else {
        res.status(404).send("Nema slika za ovu rutu");
      }
    } catch (err) {
      console.error("Greška pri dohvaćanju slika:", err);
      res.status(500).send("Greška na serveru");
    }
  })
);
app.put("/updateRoute/:routeId", (req, res) =>
  __awaiter(void 0, void 0, void 0, function* () {
    const routeId = req.params.routeId;
    const { route_name, route_description, image_urls } = req.body;
    const updateQuery = `
    UPDATE route 
    SET route_name = ?, route_description = ? 
    WHERE id = ?
  `;
    try {
      const [updateResult] = yield connection.execute(updateQuery, [
        route_name,
        route_description,
        routeId,
      ]);
      if (image_urls && image_urls.length > 0) {
        const placeholders = image_urls.map(() => "?").join(",");
        console.log("placeholder " + placeholders);
        const deleteQuery = `
        DELETE FROM route_images 
        WHERE route_id = ? AND image_url NOT IN (${placeholders})
      `;
        yield connection.execute(deleteQuery, [routeId, ...image_urls]);
      } else {
        yield connection.execute(
          "DELETE FROM route_images WHERE route_id = ?",
          [routeId]
        );
      }
      return res.status(200).send("Uspješno updateana ruta i slike!");
    } catch (err) {
      console.error(err);
      return res.status(503).send("Greška na serveru: " + err);
    }
  })
);
app.put("/updateExistingRoute/:routeId", (req, res) =>
  __awaiter(void 0, void 0, void 0, function* () {
    const routeId = req.params.routeId;
    const {
      route_name,
      route_description,
      route_data,
      duration,
      average_speed,
      distance,
      image_urls,
      image_geolocations,
    } = req.body;
    if (
      !route_name ||
      !route_description ||
      !route_data ||
      !duration ||
      !average_speed ||
      !distance
    ) {
      return res.status(400).json({
        message:
          "Sva polja su obavezna: route_name, route_description, route_data, duration, average_speed i distance",
      });
    }
    try {
      const updateRouteQuery = `UPDATE route
      SET route_name = ?, 
          route_description = ?, 
          route_data = ?, 
          duration = ?, 
          average_speed = ?, 
          distance = ? 
      WHERE id = ?`;
      const [updateResult] = yield connection.execute(updateRouteQuery, [
        route_name,
        route_description,
        route_data,
        duration,
        average_speed,
        distance,
        routeId,
      ]);
      yield connection.execute("DELETE FROM route_images WHERE route_id = ?", [
        routeId,
      ]);
      if (
        image_urls &&
        image_urls.length > 0 &&
        image_geolocations &&
        image_geolocations.length === image_urls.length
      ) {
        const insertImageQuery = `
        INSERT INTO route_images (route_id, image_url, image_geolocation) 
        VALUES (?, ?, ?)`;
        for (let i = 0; i < image_urls.length; i++) {
          yield connection.execute(insertImageQuery, [
            routeId,
            image_urls[i],
            JSON.stringify(image_geolocations[i]),
          ]);
        }
      }
      res.status(200).send("Uspješno ažurirana ruta i slike!");
    } catch (err) {
      console.error(err);
      res.status(503).send("Server ne radi ");
    }
  })
);
app.get("/publishedRoutes", (req, res) =>
  __awaiter(void 0, void 0, void 0, function* () {
    try {
      const query = `SELECT 
    route.*, 
    users.name AS user_name, 
    users.profile_image, 
    GROUP_CONCAT(route_images.image_url) AS images
FROM pistracker.route
JOIN users ON route.user_id = users.id
LEFT JOIN route_images ON route.id = route_images.route_id
WHERE route.published IS NOT NULL
GROUP BY route.id;
`;
      const [rows] = yield connection.execute(query);
      const result = rows.map((row) => ({
        route: {
          id: row.id,
          route_name: row.route_name,
          route_description: row.route_description,
          user_id: row.user_id,
          duration: row.duration,
          distance: row.distance,
          route_data: row.route_data,
        },
        user: {
          id: row.user_id,
          name: row.user_name,
          profile_image: row.profile_image,
        },
        images: row.images
          ? row.images.split(",").map((url) => ({ image_url: url }))
          : [],
      }));
      res.status(200).send(result);
    } catch (err) {
      res.status(503).send("Server nije upaljen!");
    }
  })
);
app.delete("/deleteUserAccount/:id", (req, res) =>
  __awaiter(void 0, void 0, void 0, function* () {
    const userId = req.params.id;
    const deleteRoutes = "DELETE FROM route WHERE user_id = ?";
    const deleteUserAccount = "DELETE FROM users WHERE id = ?";
    try {
      yield connection.execute(deleteRoutes, [userId]);
      const [deleteResult] = yield connection.execute(deleteUserAccount, [
        userId,
      ]);
      if (deleteResult.affectedRows > 0) {
        res.status(200).send("Korisnik i njegove rute su obrisani.");
      } else {
        res.status(404).send("Korisnik nije pronađen.");
      }
    } catch (err) {
      console.error("Greška pri brisanju korisnika:", err);
      res.status(500).send("Greška na serveru prilikom brisanja korisnika.");
    }
  })
);
app.post("/report-user", (req, res) =>
  __awaiter(void 0, void 0, void 0, function* () {
    const {
      reporter_id,
      reported_user_id,
      reason,
      message,
      location_ids,
      route_id,
    } = req.body;
    const selectReasonIdQuery = `SELECT id FROM report_reasons WHERE name = ?`;
    const insertLocationsQuery = `
    INSERT INTO report_report_locations (report_id, location_id)
    VALUES (?, ?)
  `;
    const conn = yield connection.getConnection();
    try {
      yield conn.beginTransaction();
      const [reasonRows] = yield conn.execute(selectReasonIdQuery, [
        String(reason || "").trim(),
      ]);
      if (!Array.isArray(reasonRows) || reasonRows.length === 0) {
        yield conn.rollback();
        return res.status(400).json({ message: "Nepoznat reason." });
      }
      const reasonId = reasonRows[0].id;
      if (route_id != null) {
        const [rowsOwner] = yield conn.execute(
          "SELECT user_id FROM route WHERE id = ? LIMIT 1",
          [route_id]
        );
        const owner =
          Array.isArray(rowsOwner) && rowsOwner[0]
            ? rowsOwner[0].user_id
            : null;
        if (!owner || owner !== reported_user_id) {
          yield conn.rollback();
          return res
            .status(400)
            .json({ message: "Ruta ne pripada prijavljenom korisniku." });
        }
      }
      const [reportResult] = yield conn.execute(
        `INSERT INTO reports (reporter_id, reported_user_id, reason_id, message, route_id)
       VALUES (?, ?, ?, ?, ?)`,
        [
          reporter_id,
          reported_user_id,
          reasonId,
          (message || "").trim(),
          route_id !== null && route_id !== void 0 ? route_id : null,
        ]
      );
      const reportId = reportResult.insertId;
      if (Array.isArray(location_ids) && location_ids.length > 0) {
        for (const locId of location_ids) {
          yield conn.execute(insertLocationsQuery, [reportId, locId]);
        }
      }
      yield conn.commit();
      return res
        .status(201)
        .json({ id: reportId, message: "Prijava spremljena." });
    } catch (err) {
      yield conn.rollback();
      console.error("Greška pri spremanju prijave:", err);
      return res
        .status(500)
        .json({ message: "Greška na serveru prilikom spremanja prijave." });
    } finally {
      conn.release();
    }
  })
);
app.get("/reports", (req, res) =>
  __awaiter(void 0, void 0, void 0, function* () {
    try {
      const { status } = req.query;
      const allowed = new Set(["open", "resolved", "rejected"]);
      const where =
        status && allowed.has(String(status)) ? "WHERE r.status = ?" : "";
      const params = where ? [status] : [];
      const query = `
      SELECT r.id,
             r.reporter_id,  u1.name AS reporter_name,
             r.reported_user_id, u2.name AS reported_user_name,
             r.reason_id, rr.name AS reason_name,
             r.message, r.created_at,
             r.status, r.resolved_by, r.resolved_at, r.resolution_note,
            r.route_id,rt.route_name,  
             GROUP_CONCAT(DISTINCT rl.name ORDER BY rl.name SEPARATOR ',') AS locations
      FROM reports r
      LEFT JOIN users u1 ON u1.id = r.reporter_id
      LEFT JOIN users u2 ON u2.id = r.reported_user_id
      LEFT JOIN report_reasons rr ON rr.id = r.reason_id
      LEFT JOIN report_report_locations rrl ON rrl.report_id = r.id
      LEFT JOIN report_locations rl ON rl.id = rrl.location_id
      LEFT JOIN route rt ON rt.id = r.route_id
      ${where}
      GROUP BY r.id
      ORDER BY r.created_at DESC;
    `;
      const [rows] = yield connection.execute(query, params);
      const result = rows.map((row) => {
        var _a, _b;
        return {
          id: row.id,
          reporter_name: row.reporter_name,
          reported_user_name: row.reported_user_name,
          reporter_id: row.reporter_id,
          reported_user_id: row.reported_user_id,
          reason_id: row.reason_id,
          reason_name: row.reason_name,
          message: row.message,
          created_at: row.created_at
            ? new Date(row.created_at).toISOString()
            : null,
          status: row.status,
          resolved_by: row.resolved_by,
          resolved_at: row.resolved_at,
          resolution_note: row.resolution_note,
          locations: row.locations
            ? String(row.locations)
                .split(",")
                .map((name) => ({ name }))
            : [],
          route_id: (_a = row.route_id) !== null && _a !== void 0 ? _a : null,
          route_name:
            (_b = row.route_name) !== null && _b !== void 0 ? _b : null,
        };
      });
      res.status(200).send(result);
    } catch (err) {
      res.status(503).send("Server nije upaljen!");
    }
  })
);
app.put("/reports/:id/resolve", (req, res) =>
  __awaiter(void 0, void 0, void 0, function* () {
    const { id } = req.params;
    const { admin_id, note } = req.body;
    if (!admin_id)
      return res.status(400).json({ message: "admin_id je obavezan." });
    try {
      const [result] = yield connection.execute(
        `UPDATE reports
         SET status = 'resolved',
             resolved_by = ?,
             resolved_at = NOW(),
             resolution_note = ?
       WHERE id = ? AND status = 'open'`,
        [admin_id, note !== null && note !== void 0 ? note : null, id]
      );
      if (result.affectedRows === 0) {
        return res
          .status(409)
          .json({ message: "Prijava ne postoji ili nije u statusu 'open'." });
      }
      return res.sendStatus(204);
    } catch (err) {
      console.error("resolve error:", err);
      return res.status(500).json({ message: "Greška na serveru." });
    }
  })
);
app.put("/reports/:id/reject", (req, res) =>
  __awaiter(void 0, void 0, void 0, function* () {
    const { id } = req.params;
    const { admin_id, note } = req.body;
    if (!admin_id)
      return res.status(400).json({ message: "admin_id je obavezan." });
    try {
      const [result] = yield connection.execute(
        `UPDATE reports
         SET status = 'rejected',
             resolved_by = ?,
             resolved_at = NOW(),
             resolution_note = ?
       WHERE id = ? AND status = 'open'`,
        [admin_id, note !== null && note !== void 0 ? note : null, id]
      );
      if (result.affectedRows === 0) {
        return res
          .status(409)
          .json({ message: "Prijava ne postoji ili nije u statusu 'open'." });
      }
      return res.sendStatus(204);
    } catch (err) {
      console.error("reject error:", err);
      return res.status(500).json({ message: "Greška na serveru." });
    }
  })
);
app.get("/getAllRoutes/:userId", (req, res) =>
  __awaiter(void 0, void 0, void 0, function* () {
    const userId = Number(req.params.userId);
    if (!Number.isInteger(userId)) {
      return res.status(400).json({ message: "Neispravan userId" });
    }
    try {
      const query =
        "SELECT * FROM pistracker.route WHERE user_id= ? ORDER BY created_at DESC";
      const [queryResoult] = yield connection.execute(query, [userId]);
      res.status(200).send(queryResoult);
    } catch (err) {
      console.error(err);
      return res.status(500).json({ message: "Greška na serveru" });
    }
  })
);
app.get("/getAllPublishedRoutes/:userId", (req, res) =>
  __awaiter(void 0, void 0, void 0, function* () {
    const userId = Number(req.params.userId);
    if (!Number.isInteger(userId)) {
      return res.status(400).json({ message: "Neispravan userId" });
    }
    try {
      const query =
        "SELECT * FROM pistracker.route WHERE user_id= ? AND published IS NOT NULL ORDER BY created_at DESC";
      const [queryResoult] = yield connection.execute(query, [userId]);
      res.status(200).send(queryResoult);
    } catch (err) {
      console.error(err);
      return res.status(500).json({ message: "Greška na serveru" });
    }
  })
);
app.get("/getWeeklyDuration/:userId", (req, res) =>
  __awaiter(void 0, void 0, void 0, function* () {
    const userId = Number(req.params.userId);
    if (!Number.isInteger(userId)) {
      return res.status(400).json({ message: "Neispravan userId" });
    }
    try {
      const query = `SELECT
  DATE_FORMAT(
      DATE_SUB(created_at, INTERVAL WEEKDAY(created_at) DAY),
      '%Y-%m-%d'
  ) AS label,  -- početak tjedna (ponedjeljak)
  SUM(CAST(distance AS DECIMAL(12,2))) AS meters_total
FROM route
WHERE user_id = ?
  AND created_at >= DATE_SUB(CURDATE(), INTERVAL 12 WEEK)
GROUP BY DATE_FORMAT(DATE_SUB(created_at, INTERVAL WEEKDAY(created_at) DAY), '%Y-%m-%d')
ORDER BY label;`;
      const [result] = yield connection.execute(query, [userId]);
      res.status(200).send(result);
    } catch (err) {
      console.error(err);
      return res
        .status(500)
        .json({ message: "Greška pri dohvaćanju statistike" });
    }
  })
);
app.listen(3000, () => {
  console.log("Server is listening on port 3000 PisTracker");
});
