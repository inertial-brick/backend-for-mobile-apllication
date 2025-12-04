import { compare, hash } from "bcrypt";
import express, { query } from "express";
import { sign, verify } from "jsonwebtoken";
import { createPool, PoolOptions, ResultSetHeader } from "mysql2";
import mysql, { RowDataPacket } from "mysql2/promise";
import { createTransport } from "nodemailer";
import { UserWithRoutes } from "./types";
import { env, signupValidation } from "./utils";
import cors from "cors";

const app = express();
app.use(express.json());
app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE"],
  })
);

app.get("/health", (_req, res) => {
  res.send("ok");
});
const connection = mysql.createPool({
  host: env.DB_HOST,
  user: env.DB_USER,
  password: env.DB_PASSWORD,
  database: env.DB_NAME,
  port: env.DB_PORT,
});

connection
  .getConnection()
  .then(() => {})
  .catch((err) => {});

const transport = createTransport({
  host: "sandbox.smtp.mailtrap.io",
  port: 2525,
  auth: {
    user: "57d3efe575c94e",
    pass: "bb6d2a42e9228f",
  },
});

app.post("/signup", async (req, res) => {
  try {
    const input = signupValidation.parse(req.body);
    const hashedPassword = await hash(input.password, 10);
    const about = "";
    const profile_image = "";
    const query =
      "INSERT INTO users (name, email, password, about, profile_image) VALUES (?, ?, ?,?,?)";
    const [result] = await connection.execute<ResultSetHeader>(query, [
      input.name,
      input.email,
      hashedPassword,
      about,
      profile_image,
    ]);
    if (result.affectedRows != 1) {
      return res.status(500).send("Error registering user");
    }
    res.status(201).send("User registered successfully");
  } catch (err) {
    res.status(500).send("Error registering user");
  }
});

app.post("/login", async (req, res) => {
  const { email, password }: { email: string; password: string } = req.body;
  const query = "SELECT * FROM  users WHERE email = ?";
  try {
    const [results] = await connection.execute<RowDataPacket[]>(query, [email]);
    if (results.length === 0) {
      return res.status(404).send("Korisnik nije pronađen");
    }
    const comparison = await compare(password, results[0].password);
    if (!comparison) {
      return res.status(401).send("Krivo upisan lozinka");
    }
    const secretKey = "your-secret-secret";
    const accessToken = sign(
      { id: results[0].id, email: results[0].email },
      secretKey,
      { expiresIn: "1h" }
    );
    const refreshToken = sign(
      { id: results[0].id, email: results[0].email },
      env.REFRESH_SECRET,
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
    return res.status(500).send("Error logging in");
  }
});

app.post("/refresh-token", (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) {
    res.status(401).send("Refresh Token is required");
    return;
  }
  try {
    const user = verify(refreshToken, process.env.JWT_SECRET ?? "");
    if (typeof user === "string") {
      throw new Error("Decoded user not valid payload");
    }
    const accessToken = sign(
      {
        id: user?.id,
        email: user?.email,
      },
      process.env.JWT_SECRET ?? "",
      { expiresIn: "1h" }
    );
    res.status(200).send({
      accessToken,
    });
  } catch (err) {
    res.status(500).send("Error refreshing token");
  }
});

app.put("/updateUser", async (req, res) => {
  const {
    id,
    name,
    email,
    about,
  }: {
    id: number;
    name: string;
    email: string;
    about: string | null | undefined;
  } = req.body;
  const query = "UPDATE users SET name = ?, email = ?, about = ? WHERE id = ?";
  try {
    const [results] = await connection.execute(query, [name, email, about, id]);
    if (results) {
      res.status(200).send({ name, email, about });
    } else {
      res.status(500).send("Response nije dobar");
    }
  } catch (err) {
    res.status(400).send("nešto ne štima");
  }
});

app.get("/users/:id", async (req, res) => {
  const userId = parseInt(req.params.id, 10);
  const requestingUserId = req.query.requesting_user_id
    ? parseInt(req.query.requesting_user_id as string, 10)
    : null;

  try {
    const [adminBlock] = await connection.execute<RowDataPacket[]>(
      "SELECT id FROM blocked_users WHERE blocked_user_id = ? AND is_admin_block = 1",
      [userId]
    );

    if (adminBlock.length > 0) {
      return res.status(404).json({ message: "User not found" });
    }

    if (requestingUserId) {
      const [userBlock] = await connection.execute<RowDataPacket[]>(
        "SELECT id FROM blocked_users WHERE blocker_id = ? AND blocked_user_id = ? AND is_admin_block = 0",
        [requestingUserId, userId]
      );

      if (userBlock.length > 0) {
        return res.status(404).json({ message: "User not found" });
      }
    }

    const [userResult] = await connection.execute<RowDataPacket[]>(
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
    const [routesResult] = await connection.execute<RowDataPacket[]>(
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
        ? route.images.split(",").map((url: string) => ({ image_url: url }))
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
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/user/:id/profile-image", async (req, res) => {
  const { user_id, profileImageUrl } = req.body;
  const query = "UPDATE users SET profile_image = ? WHERE id = ?";
  try {
    const [result] = await connection.execute<ResultSetHeader>(query, [
      profileImageUrl,
      user_id,
    ]);
    if (result.affectedRows === 0) {
      return res.status(404).send("user nije pronađen");
    }
    res.status(200).send("Slika uspješno postavljena !");
  } catch (err) {
    res.status(500).send("Ne uspjeh u ažuriranju");
  }
});

app.put("/changePassword", async (req, res) => {
  const {
    id,
    currentPassword,
    newPassword,
  }: { id: number; currentPassword: string; newPassword: string } = req.body;
  const query = "SELECT password FROM users WHERE id = ?";
  try {
    const [result] = await connection.execute<RowDataPacket[]>(query, [id]);
    if (result.length > 0) {
      const storedPassword = result[0].password;
      const passwordIsValid = await compare(currentPassword, storedPassword);
      if (passwordIsValid) {
        const hashedNewPassword: string = await hash(newPassword, 10);
        const updateQuery = "UPDATE users SET password = ? WHERE id = ? ";
        const [updatePassword] = await connection.execute<ResultSetHeader>(
          updateQuery,
          [hashedNewPassword, id]
        );
        if (updatePassword.affectedRows > 0) {
          res.status(200).send("Uspješno ažuriranje passworda !");
        } else {
          res.status(400).send("Loš response!");
        }
      } else {
        res.status(400).send("Krivo upisana stara šifra!");
      }
    }
  } catch (err) {
    res.status(500).send("Greška sa serverom!");
  }
});

app.put("/changeEmail", async (req, res) => {
  const {
    id,
    currentEmail,
    newEmail,
  }: { id: number; currentEmail: string; newEmail: string } = req.body;
  const query = "SELECT email FROM users WHERE id = ?";
  try {
    const [result] = await connection.execute<RowDataPacket[]>(query, [id]);
    if (result.length > 0) {
      const storedEmail = result[0].email;
      if (storedEmail === currentEmail) {
        const updateQuery = "UPDATE users SET email = ? WHERE id = ? ";
        const [updateEmail] = await connection.execute<ResultSetHeader>(
          updateQuery,
          [newEmail, id]
        );
        if (updateEmail.affectedRows > 0) {
          res.status(200).send("Uspješno ažuriranje emaila !");
        } else {
          res.status(400).send("Loš response!");
        }
      } else {
        res.status(400).send("Email ne odgovara postojećem.");
      }
    }
  } catch (err) {
    res.status(500).send("Greška sa serverom!");
  }
});

const normalizeNumber = (value: unknown) => {
  if (value === null || value === undefined || value === "") return null;
  const parsed = Number(String(value).replace(",", "."));
  return Number.isFinite(parsed) ? parsed : null;
};

const normalizeRouteData = (data: unknown) => {
  if (Array.isArray(data)) return JSON.stringify(data);
  if (typeof data === "string") return data;
  throw new Error("route_data mora biti lista točaka");
};

app.post("/saveRoute", async (req, res) => {
  try {
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
      route_type,
    } = req.body;

    const routeDataJson = normalizeRouteData(route_data);
    const normalizedDuration = normalizeNumber(duration);
    const normalizedDistance = normalizeNumber(distance);
    const normalizedSpeed = normalizeNumber(average_speed);

    if (normalizedDuration === null || normalizedDistance === null) {
      return res.status(400).send("duration i distance su obavezni brojevi");
    }

    const query = `
      INSERT INTO route (
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
        route_type
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    const params = [
      user_id,
      routeDataJson,
      normalizedDuration,
      normalizedSpeed,
      normalizedDistance,
      route_name ?? null,
      route_description ?? null,
      city ?? null,
      region ?? null,
      country ?? null,
      route_type ?? null,
    ];

    const [result] = await connection.execute<ResultSetHeader>(query, params);

    if (result.affectedRows > 0) {
      return res.status(200).send({ id: result.insertId });
    }

    res.status(400).send("Loš request");
  } catch (err) {
    res.status(503).send("Server nije upaljen");
  }
});

app.post("/saveImage", async (req, res) => {
  const { route_id, image_url, image_geolocation } = req.body;

  if (!route_id || !image_url || !image_geolocation) {
    return res.status(400).send("Missing required fields");
  }

  try {
    let geo = image_geolocation;
    if (Array.isArray(image_geolocation) && image_geolocation.length === 2) {
      geo = { lat: image_geolocation[1], lng: image_geolocation[0] };
    }

    const query =
      "INSERT INTO route_images (route_id, image_url, image_geolocation) VALUES (?, ?, ?)";
    const [result] = await connection.execute<ResultSetHeader>(query, [
      route_id,
      image_url,
      JSON.stringify(geo),
    ]);

    if (result.affectedRows > 0) {
      return res.status(200).send("Uspješno dodana slika/slike!");
    } else {
      return res.status(400).send("Niste uspjeli dodati sliku!");
    }
  } catch (err) {
    res.status(500).send("Server nije upaljen!");
  }
});

app.get("/getRoutes/:userId", async (req, res) => {
  const userId = Number(req.params.userId);
  const query = "SELECT * FROM route WHERE user_id = ? ";
  try {
    const [result] = await connection.execute<RowDataPacket[]>(query, [userId]);
    if (result.length > 0) {
      res.status(200).send(result);
    } else {
      res.status(404).send("Nema pronađenih ruta!");
    }
  } catch (err) {
    res.status(500).send("Greška na serveru");
  }
});

app.delete("/deleteRoute/:id", async (req, res) => {
  const routeId = req.params.id;
  const deleteImagesQuery = "DELETE FROM route_images WHERE route_id = ?";
  const deleteRouteQuery = "DELETE FROM route WHERE id = ?";
  try {
    const [deletedImagesResult] = await connection.execute<ResultSetHeader>(
      deleteImagesQuery,
      [routeId]
    );
    const [deleteRouteResult] = await connection.execute<ResultSetHeader>(
      deleteRouteQuery,
      [routeId]
    );
    if (deleteRouteResult.affectedRows > 0) {
      res.status(200).send("Ruta uspješno obrisana.");
    } else {
      res.status(404).send("Ruta nije pronađena!");
    }
  } catch (err) {
    res.status(503).send("Server nije u mogućnosti napraviti taj zahtjev!");
  }
});

app.post("/makePrivate/:id", async (req, res) => {
  const routeId = req.params.id;
  const query = "UPDATE route SET published = NULL WHERE id = ?";
  try {
    const [result] = await connection.execute<ResultSetHeader>(query, [
      routeId,
    ]);
    if (result.affectedRows > 0) {
      res.status(200).send("Ruta je privatna!");
    } else {
      res.status(400).send("Krivi query!");
    }
  } catch (err) {
    res.status(503).send("Servner ne radi!");
  }
});

app.post("/publishRoute/:id", async (req, res) => {
  const routeId = req.params.id;
  const query = "UPDATE route SET published = NOW() WHERE id = ?";
  try {
    const [result] = await connection.execute<ResultSetHeader>(query, [
      routeId,
    ]);
    if (result.affectedRows > 0) {
      res.status(200).send("Ruta je uplodana!");
    } else {
      res.status(400).send("Krivi query!");
    }
  } catch (err) {
    res.status(503).send("Servner ne radi!");
  }
});

app.get("/getRouteDetails/:routeId", async (req, res) => {
  const routeId = req.params.routeId;
  const query = "SELECT * FROM route WHERE id = ?";
  try {
    const [result] = await connection.execute<RowDataPacket[]>(query, [
      routeId,
    ]);
    if (result.length > 0) {
      res.status(200).send(result[0]);
    } else {
      res.status(400).send("Krivi query");
    }
  } catch (err) {
    res.status(503).send("Server ne radi");
  }
});

app.get("/getRouteWithUser/:routeId", async (req, res) => {
  const routeId = req.params.routeId;
  const requestingUserId = req.query.requesting_user_id
    ? parseInt(req.query.requesting_user_id as string, 10)
    : null;

  const query = `
    SELECT 
      route.*, 
      users.id AS user_id, users.name AS user_name, users.profile_image,
      GROUP_CONCAT(ri.image_url) AS image_urls
    FROM route
    JOIN users ON users.id = route.user_id
    LEFT JOIN route_images ri ON route.id = ri.route_id
    WHERE route.id = ? AND route.distance >= 50
    GROUP BY route.id;
  `;
  try {
    const [result] = await connection.execute<RowDataPacket[]>(query, [
      routeId,
    ]);
    if (result.length > 0) {
      const row = result[0];
      const userId = row.user_id;

      const [adminBlock] = await connection.execute<RowDataPacket[]>(
        "SELECT id FROM blocked_users WHERE blocked_user_id = ? AND is_admin_block = 1",
        [userId]
      );

      if (adminBlock.length > 0) {
        return res.status(404).send("Ruta nije pronađena");
      }

      if (requestingUserId) {
        const [userBlock] = await connection.execute<RowDataPacket[]>(
          "SELECT id FROM blocked_users WHERE blocker_id = ? AND blocked_user_id = ? AND is_admin_block = 0",
          [requestingUserId, userId]
        );

        if (userBlock.length > 0) {
          return res.status(404).send("Ruta nije pronađena");
        }
      }

      const images = row.image_urls
        ? row.image_urls.split(",").map((url: string) => ({ image_url: url }))
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
          route_type: row.route_type || null,
          city: row.city || null,
          region: row.region || null,
          country: row.country || null,
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
    res.status(500).send("Došlo je do pogreške na serveru");
  }
});

app.get("/getRouteImages/:routeId", async (req, res) => {
  const routeId = req.params.routeId;
  const query =
    "SELECT image_url, image_geolocation FROM route_images WHERE route_id = ?";

  try {
    const [result] = await connection.execute<RowDataPacket[]>(query, [
      routeId,
    ]);

    if (result.length > 0) {
      const formattedImages = result.map((row) => {
        let geolocation = null;

        try {
          if (
            row.image_geolocation === null ||
            row.image_geolocation === undefined
          ) {
            return {
              image_url: row.image_url,
              image_geolocation: null,
            };
          }

          if (
            typeof row.image_geolocation === "object" &&
            row.image_geolocation !== null
          ) {
            if (
              Array.isArray(row.image_geolocation) &&
              row.image_geolocation.length === 2
            ) {
              geolocation = {
                lat: row.image_geolocation[1],
                lng: row.image_geolocation[0],
              };
            } else if (
              "lat" in row.image_geolocation &&
              "lng" in row.image_geolocation
            ) {
              geolocation = row.image_geolocation;
            }
          } else if (typeof row.image_geolocation === "string") {
            const parsed = JSON.parse(row.image_geolocation);

            if (Array.isArray(parsed) && parsed.length === 2) {
              geolocation = { lat: parsed[1], lng: parsed[0] };
            } else if (
              typeof parsed === "object" &&
              parsed !== null &&
              "lat" in parsed &&
              "lng" in parsed
            ) {
              geolocation = parsed;
            }
          }
        } catch (err) {}

        return {
          image_url: row.image_url,
          image_geolocation: geolocation,
        };
      });

      return res.status(200).json(formattedImages);
    } else {
      return res.status(404).send("Nema slika za ovu rutu");
    }
  } catch (err) {
    res.status(500).send("Greška na serveru");
  }
});

app.put("/updateRoute/:routeId", async (req, res) => {
  const routeId = req.params.routeId;
  const { route_name, route_description, image_urls } = req.body;
  const updateQuery = `
    UPDATE route 
    SET route_name = ?, route_description = ? 
    WHERE id = ?
  `;
  try {
    const [updateResult] = await connection.execute<ResultSetHeader>(
      updateQuery,
      [route_name, route_description, routeId]
    );
    if (image_urls && image_urls.length > 0) {
      const placeholders = image_urls.map(() => "?").join(",");
      const deleteQuery = `
        DELETE FROM route_images 
        WHERE route_id = ? AND image_url NOT IN (${placeholders})
      `;
      await connection.execute<ResultSetHeader>(deleteQuery, [
        routeId,
        ...image_urls,
      ]);
    } else {
      await connection.execute("DELETE FROM route_images WHERE route_id = ?", [
        routeId,
      ]);
    }
    return res.status(200).send("Uspješno updateana ruta i slike!");
  } catch (err) {
    return res.status(503).send("Greška na serveru: " + err);
  }
});

app.put("/updateExistingRoute/:routeId", async (req, res) => {
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
  }: {
    route_name: string;
    route_description: string;
    route_data: JSON;
    duration: number;
    average_speed: string;
    distance: string;
    image_urls?: string[];
    image_geolocations?: JSON[];
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
    const [updateResult] = await connection.execute<ResultSetHeader>(
      updateRouteQuery,
      [
        route_name,
        route_description,
        route_data,
        duration,
        average_speed,
        distance,
        routeId,
      ]
    );
    await connection.execute("DELETE FROM route_images WHERE route_id = ?", [
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
        await connection.execute(insertImageQuery, [
          routeId,
          image_urls[i],
          JSON.stringify(image_geolocations[i]),
        ]);
      }
    }
    res.status(200).send("Uspješno ažurirana ruta i slike!");
  } catch (err) {
    res.status(503).send("Server ne radi ");
  }
});

app.get("/publishedRoutes", async (req, res) => {
  const requestingUserId = req.query.requesting_user_id
    ? parseInt(req.query.requesting_user_id as string, 10)
    : null;

  try {
    let blockFilter = "";
    const queryParams: any[] = [];

    if (requestingUserId) {
      blockFilter = `
        AND route.user_id NOT IN (
          SELECT blocked_user_id 
          FROM blocked_users 
          WHERE is_admin_block = 1
        )
        AND route.user_id NOT IN (
          SELECT blocked_user_id 
          FROM blocked_users 
          WHERE blocker_id = ? AND is_admin_block = 0
        )
      `;
      queryParams.push(requestingUserId);
    } else {
      blockFilter = `
        AND route.user_id NOT IN (
          SELECT blocked_user_id 
          FROM blocked_users 
          WHERE is_admin_block = 1
        )
      `;
    }

    const query = `SELECT 
      route.*, 
      users.name AS user_name, 
      users.profile_image, 
      GROUP_CONCAT(route_images.image_url) AS images
    FROM route
    JOIN users ON route.user_id = users.id
    LEFT JOIN route_images ON route.id = route_images.route_id
    WHERE route.published IS NOT NULL AND route.distance >= 50
    ${blockFilter}
    GROUP BY route.id;
    `;

    const [rows] = await connection.execute<RowDataPacket[]>(
      query,
      queryParams
    );

    const result = rows.map((row) => ({
      route: {
        id: row.id,
        route_name: row.route_name,
        route_description: row.route_description,
        user_id: row.user_id,
        duration: row.duration,
        distance: row.distance,
        route_data: row.route_data,
        city: row.city,
        region: row.region,
        country: row.country,
        published: row.published,
      },
      user: {
        id: row.user_id,
        name: row.user_name,
        profile_image: row.profile_image,
      },
      images: row.images
        ? row.images.split(",").map((url: string) => ({ image_url: url }))
        : [],
    }));

    res.status(200).send(result);
  } catch (err) {
    res.status(503).send("Server nije upaljen!");
  }
});

app.delete("/deleteUserAccount/:id", async (req, res) => {
  const userId = req.params.id;
  const deleteRoutes = "DELETE FROM route WHERE user_id = ?";
  const deleteUserAccount = "DELETE FROM users WHERE id = ?";
  try {
    await connection.execute(deleteRoutes, [userId]);
    const [deleteResult] = await connection.execute<ResultSetHeader>(
      deleteUserAccount,
      [userId]
    );
    if (deleteResult.affectedRows > 0) {
      res.status(200).send("Korisnik i njegove rute su obrisani.");
    } else {
      res.status(404).send("Korisnik nije pronađen.");
    }
  } catch (err) {
    res.status(500).send("Greška na serveru prilikom brisanja korisnika.");
  }
});

app.post("/block-user", async (req, res) => {
  const { blocker_id, blocked_user_id } = req.body;

  if (!blocker_id || !blocked_user_id) {
    return res
      .status(400)
      .json({ message: "blocker_id i blocked_user_id su obavezni" });
  }

  if (blocker_id === blocked_user_id) {
    return res
      .status(400)
      .json({ message: "Korisnik ne može blokirati samog sebe" });
  }

  try {
    const [userResult] = await connection.execute<RowDataPacket[]>(
      "SELECT role FROM users WHERE id = ?",
      [blocker_id]
    );

    if (userResult.length === 0) {
      return res
        .status(404)
        .json({ message: "Korisnik koji blokira nije pronađen" });
    }

    const isAdmin = userResult[0].role === "admin";

    const [existingBlock] = await connection.execute<RowDataPacket[]>(
      "SELECT id FROM blocked_users WHERE blocker_id = ? AND blocked_user_id = ?",
      [blocker_id, blocked_user_id]
    );

    if (existingBlock.length > 0) {
      return res.status(409).json({ message: "Korisnik je već blokiran" });
    }

    if (isAdmin) {
      const [adminBlock] = await connection.execute<RowDataPacket[]>(
        "SELECT id FROM blocked_users WHERE blocked_user_id = ? AND is_admin_block = 1",
        [blocked_user_id]
      );

      if (adminBlock.length > 0) {
        return res
          .status(409)
          .json({ message: "Korisnik je već blokiran od strane admina" });
      }

      await connection.execute(
        "DELETE FROM blocked_users WHERE blocked_user_id = ? AND is_admin_block = 0",
        [blocked_user_id]
      );

      const [result] = await connection.execute<ResultSetHeader>(
        "INSERT INTO blocked_users (blocker_id, blocked_user_id, is_admin_block) VALUES (?, ?, 1)",
        [blocker_id, blocked_user_id]
      );

      return res.status(201).json({
        message: "Korisnik je blokiran od strane admina",
        id: result.insertId,
      });
    } else {
      const [adminBlock] = await connection.execute<RowDataPacket[]>(
        "SELECT id FROM blocked_users WHERE blocked_user_id = ? AND is_admin_block = 1",
        [blocked_user_id]
      );

      if (adminBlock.length > 0) {
        return res
          .status(409)
          .json({ message: "Korisnik je već blokiran od strane admina" });
      }

      const [result] = await connection.execute<ResultSetHeader>(
        "INSERT INTO blocked_users (blocker_id, blocked_user_id, is_admin_block) VALUES (?, ?, 0)",
        [blocker_id, blocked_user_id]
      );

      return res.status(201).json({
        message: "Korisnik je blokiran",
        id: result.insertId,
      });
    }
  } catch (err) {
    return res
      .status(500)
      .json({ message: "Greška na serveru prilikom blokiranja korisnika" });
  }
});

app.post("/report-user", async (req, res) => {
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
  const conn = await connection.getConnection();
  try {
    await conn.beginTransaction();
    const [reasonRows] = await conn.execute(selectReasonIdQuery, [
      String(reason || "").trim(),
    ]);
    if (!Array.isArray(reasonRows) || reasonRows.length === 0) {
      await conn.rollback();
      return res.status(400).json({ message: "Nepoznat reason." });
    }
    const reasonId = (reasonRows[0] as any).id;
    if (route_id != null) {
      const [rowsOwner] = await conn.execute(
        "SELECT user_id FROM route WHERE id = ? LIMIT 1",
        [route_id]
      );
      const owner =
        Array.isArray(rowsOwner) && rowsOwner[0]
          ? (rowsOwner[0] as any).user_id
          : null;
      if (!owner || owner !== reported_user_id) {
        await conn.rollback();
        return res
          .status(400)
          .json({ message: "Ruta ne pripada prijavljenom korisniku." });
      }
    }
    const [reportResult] = await conn.execute<ResultSetHeader>(
      `INSERT INTO reports (reporter_id, reported_user_id, reason_id, message, route_id)
       VALUES (?, ?, ?, ?, ?)`,
      [
        reporter_id,
        reported_user_id,
        reasonId,
        (message || "").trim(),
        route_id ?? null,
      ]
    );
    const reportId = (reportResult as ResultSetHeader).insertId;
    if (Array.isArray(location_ids) && location_ids.length > 0) {
      for (const locId of location_ids) {
        await conn.execute(insertLocationsQuery, [reportId, locId]);
      }
    }
    await conn.commit();
    return res
      .status(201)
      .json({ id: reportId, message: "Prijava spremljena." });
  } catch (err) {
    await conn.rollback();
    return res
      .status(500)
      .json({ message: "Greška na serveru prilikom spremanja prijave." });
  } finally {
    conn.release();
  }
});

app.get("/reports", async (req, res) => {
  try {
    const { status } = req.query;
    const allowed = new Set(["open", "resolved", "rejected"]);
    const where =
      status && allowed.has(String(status)) ? "WHERE r.status = ?" : "";
    const params: any[] = where ? [status] : [];
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
    const [rows] = await connection.execute<RowDataPacket[]>(query, params);
    const result = rows.map((row: any) => ({
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
            .map((name: string) => ({ name }))
        : [],
      route_id: row.route_id ?? null,
      route_name: row.route_name ?? null,
    }));
    res.status(200).send(result);
  } catch (err) {
    res.status(503).send("Server nije upaljen!");
  }
});

app.put("/reports/:id/resolve", async (req, res) => {
  const { id } = req.params;
  const { admin_id, note } = req.body;
  if (!admin_id)
    return res.status(400).json({ message: "admin_id je obavezan." });
  try {
    const [result]: any = await connection.execute(
      `UPDATE reports
         SET status = 'resolved',
             resolved_by = ?,
             resolved_at = NOW(),
             resolution_note = ?
       WHERE id = ? AND status = 'open'`,
      [admin_id, note ?? null, id]
    );
    if (result.affectedRows === 0) {
      return res
        .status(409)
        .json({ message: "Prijava ne postoji ili nije u statusu 'open'." });
    }
    return res.sendStatus(204);
  } catch (err) {
    return res.status(500).json({ message: "Greška na serveru." });
  }
});

app.put("/reports/:id/reject", async (req, res) => {
  const { id } = req.params;
  const { admin_id, note } = req.body;
  if (!admin_id)
    return res.status(400).json({ message: "admin_id je obavezan." });
  try {
    const [result]: any = await connection.execute(
      `UPDATE reports
         SET status = 'rejected',
             resolved_by = ?,
             resolved_at = NOW(),
             resolution_note = ?
       WHERE id = ? AND status = 'open'`,
      [admin_id, note ?? null, id]
    );
    if (result.affectedRows === 0) {
      return res
        .status(409)
        .json({ message: "Prijava ne postoji ili nije u statusu 'open'." });
    }
    return res.sendStatus(204);
  } catch (err) {
    return res.status(500).json({ message: "Greška na serveru." });
  }
});

app.get("/getAllRoutes/:userId", async (req, res) => {
  const userId = Number(req.params.userId);
  if (!Number.isInteger(userId)) {
    return res.status(400).json({ message: "Neispravan userId" });
  }
  try {
    const query =
      "SELECT * FROM route WHERE user_id= ? ORDER BY created_at DESC";
    const [queryResoult] = await connection.execute<RowDataPacket[]>(query, [
      userId,
    ]);

    res.status(200).send(queryResoult);
  } catch (err) {
    return res.status(500).json({ message: "Greška na serveru" });
  }
});

app.get("/getAllPublishedRoutes/:userId", async (req, res) => {
  const userId = Number(req.params.userId);
  if (!Number.isInteger(userId)) {
    return res.status(400).json({ message: "Neispravan userId" });
  }
  try {
    const query =
      "SELECT * FROM route WHERE user_id= ? AND published IS NOT NULL AND route.distance >=50 ORDER BY created_at DESC";
    const [queryResoult] = await connection.execute<RowDataPacket[]>(query, [
      userId,
    ]);

    res.status(200).send(queryResoult);
  } catch (err) {
    return res.status(500).json({ message: "Greška na serveru" });
  }
});

app.get("/getStats/:userId", async (req, res) => {
  const userId = Number(req.params.userId);
  const period = (req.query.period as string) || "weekly";

  if (!Number.isInteger(userId)) {
    return res.status(400).json({ message: "Neispravan userId" });
  }

  try {
    let query = "";

    if (period === "daily") {
      query = `
    SELECT
  DATE_FORMAT(created_at, '%d-%m-%Y') AS label,
  SUM(CAST(distance AS DECIMAL(12,2))) AS meters_total
FROM route
WHERE user_id = ?
  AND created_at >= DATE_SUB(CURDATE(), INTERVAL 12 WEEK)
GROUP BY DATE_FORMAT(created_at, '%d-%m-%Y')
ORDER BY MIN(created_at) ASC;
  `;
    } else if (period === "weekly") {
      query = `
   SELECT
  DATE_FORMAT(MIN(created_at), '%d-%m-%Y') AS label, -- početak tjedna
  SUM(CAST(distance AS DECIMAL(12,2))) AS meters_total
FROM route
WHERE user_id = ?
  AND created_at >= DATE_SUB(CURDATE(), INTERVAL 12 WEEK)
GROUP BY YEARWEEK(created_at, 1)
ORDER BY MIN(created_at) ASC;
  `;
    } else if (period === "monthly") {
      query = `
  SELECT
  DATE_FORMAT(MIN(created_at), '%m-%Y') AS label,   -- prvi dan tog mjeseca
  SUM(CAST(distance AS DECIMAL(12,2))) AS meters_total
FROM route
WHERE user_id = ?
  AND created_at >= DATE_SUB(CURDATE(), INTERVAL 12 MONTH)
GROUP BY YEAR(created_at), MONTH(created_at)
ORDER BY MIN(created_at) ASC;
  `;
    } else if (period === "yearly") {
      query = `
  SELECT 
  DATE_FORMAT(MIN(created_at), '%Y') AS label,   
  SUM(CAST(distance AS DECIMAL(12,2))) AS meters_total
FROM route
WHERE user_id = ?
GROUP BY YEAR(created_at)
ORDER BY MIN(created_at) ASC;
  `;
    } else {
      return res.status(400).json({ message: "Nepoznat period" });
    }

    const [result] = await connection.execute<RowDataPacket[]>(query, [userId]);
    res.status(200).send(result);
  } catch (err) {
    return res
      .status(500)
      .json({ message: "Greška pri dohvaćanju statistike" });
  }
});

app.post("/goals", async (req, res) => {
  const { user_id, goal_type, target_distance, start_date, end_date } =
    req.body;

  if (!user_id || !goal_type || !target_distance || !start_date || !end_date) {
    return res.status(400).json({ message: "Nedostaju parametri." });
  }

  try {
    const query = `
      INSERT INTO goals (user_id, goal_type, target_distance, start_date, end_date)
      VALUES (?, ?, ?, ?, ?)
    `;
    const [result] = await connection.execute<ResultSetHeader>(query, [
      user_id,
      goal_type,
      target_distance,
      start_date,
      end_date,
    ]);

    res.status(201).json({ id: result.insertId, message: "Cilj spremljen!" });
  } catch (err) {
    res.status(500).json({ message: "Greška na serveru" });
  }
});

app.get("/goals/active/:userId", async (req, res) => {
  const userId = Number(req.params.userId);
  if (!Number.isInteger(userId)) {
    return res.status(400).json({ message: "Neispravan userId" });
  }

  try {
    const [goals] = await connection.execute<RowDataPacket[]>(
      `SELECT * FROM goals 
       WHERE user_id = ? 
      AND CURDATE() BETWEEN start_date AND end_date
       ORDER BY created_at DESC`,
      [userId]
    );

    if (!goals || goals.length === 0) {
      return res.status(200).json([]);
    }

    for (const goal of goals) {
      const [stats] = await connection.execute<RowDataPacket[]>(
        `SELECT COALESCE(SUM(distance), 0) AS total_km
         FROM route
         WHERE user_id = ?
           AND created_at BETWEEN ? AND ?`,
        [goal.user_id, goal.start_date, goal.end_date]
      );

      const total = stats[0].total_km;
      goal.achieved_km = total;
      goal.progress_pct = Math.min(100, (total / goal.target_distance) * 100);
      goal.remaining_km = Math.max(0, goal.target_distance - total);
      goal.is_completed = total >= goal.target_distance;
    }

    res.status(200).json(goals);
  } catch (err) {
    res.status(500).json({ message: "Greška na serveru" });
  }
});

app.get("/goals/progress/:goalId", async (req, res) => {
  const goalId = Number(req.params.goalId);

  try {
    const [rows] = await connection.execute<RowDataPacket[]>(
      "SELECT * FROM goals WHERE id = ?",
      [goalId]
    );
    if (rows.length === 0) {
      return res.status(404).json({ message: "Cilj nije pronađen" });
    }
    const goal = rows[0];

    const [stats] = await connection.execute<RowDataPacket[]>(
      `SELECT COALESCE(SUM(CAST(distance AS DECIMAL(12,2))),0) AS total_km
       FROM route
       WHERE user_id = ?
         AND created_at BETWEEN ? AND ?`,
      [goal.user_id, goal.start_date, goal.end_date]
    );

    const total = stats[0].total_km;
    const progress = Math.min(100, (total / goal.target_distance) * 100);

    res.status(200).json({
      goal,
      achieved_km: total,
      progress_pct: progress,
      remaining_km: Math.max(0, goal.target_distance - total),
      is_completed: total >= goal.target_distance,
    });
  } catch (err) {
    res.status(500).json({ message: "Greška na serveru" });
  }
});

app.get("/goals/:userId", async (req, res) => {
  const userId = Number(req.params.userId);
  if (!Number.isInteger(userId)) {
    return res.status(400).json({ message: "Neispravan userId" });
  }

  try {
    const [goals] = await connection.execute<RowDataPacket[]>(
      `SELECT * FROM goals 
       WHERE user_id = ?
       ORDER BY created_at DESC`,
      [userId]
    );

    if (!goals || goals.length === 0) {
      return res.status(200).json([]);
    }

    for (const goal of goals) {
      const [stats] = await connection.execute<RowDataPacket[]>(
        `SELECT COALESCE(SUM(distance), 0) AS total_m
         FROM route
         WHERE user_id = ?
           AND created_at BETWEEN ? AND ?`,
        [goal.user_id, goal.start_date, goal.end_date]
      );

      const totalMeters = stats[0].total_m;
      goal.achieved_km = totalMeters;
      goal.progress_pct = Math.min(
        100,
        (totalMeters / (goal.target_distance * 1000)) * 100
      );
      goal.remaining_km = Math.max(
        0,
        goal.target_distance * 1000 - totalMeters
      );
      goal.is_completed = totalMeters >= goal.target_distance * 1000;
    }

    res.status(200).json(goals);
  } catch (err) {
    res.status(500).json({ message: "Greška na serveru" });
  }
});

app.get("/goals/expired/:userId", async (req, res) => {
  const userId = Number(req.params.userId);
  if (!Number.isInteger(userId)) {
    return res.status(400).json({ message: "Neispravan userId" });
  }

  try {
    const [goals] = await connection.execute<RowDataPacket[]>(
      `SELECT * FROM goals 
       WHERE user_id = ? 
       AND end_date < CURDATE()
       ORDER BY created_at DESC`,
      [userId]
    );

    for (const goal of goals) {
      const [stats] = await connection.execute<RowDataPacket[]>(
        `SELECT COALESCE(SUM(distance), 0) AS total_m
         FROM route
         WHERE user_id = ?
           AND created_at BETWEEN ? AND ?`,
        [goal.user_id, goal.start_date, goal.end_date]
      );

      const total = stats[0].total_m;
      goal.achieved_km = total;
      goal.progress_pct = Math.min(
        100,
        (total / (goal.target_distance * 1000)) * 100
      );
      goal.remaining_km = Math.max(0, goal.target_distance * 1000 - total);
      goal.is_completed = total >= goal.target_distance * 1000;
    }

    res.status(200).json(goals);
  } catch (err) {
    res.status(500).json({ message: "Greška na serveru" });
  }
});

app.delete("/goals/:id", async (req, res) => {
  const { id } = req.params;

  if (!id) {
    return res.status(400).json({ message: "ID cilja nije poslan." });
  }
  const deleteQuery = "DELETE FROM goals WHERE id = ?";
  try {
    const [result] = await connection.execute<ResultSetHeader>(deleteQuery, [
      id,
    ]);

    if ((result as any).affectedRows > 0) {
      res.status(200).json({ message: "Cilj obrisan." });
    } else {
      res.status(404).json({ message: "Cilj nije pronađen." });
    }
  } catch (err) {
    res.status(500).json({ message: "Greška na serveru." });
  }
});

const PORT = Number(process.env.PORT || 3000);
app.listen(PORT, () => {});
