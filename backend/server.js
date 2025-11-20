const express = require("express");
const session = require("express-session");
const {Totp} = require("time2fa");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const db = require("./firestore");
const QRCode = require('qrcode');
const path = require("path");

require('dotenv').config();



const app = express();



app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "../frontend/views"));


app.use(express.json());
app.use(express.urlencoded({ extended: true }));


app.use(session({
    secret: process.env['Session-Secret'],
    resave: false,
    saveUninitialized: false
}));


app.use(passport.initialize());
app.use(passport.session());


// (OIDC / Google IdP) Google OAuth Strategy
passport.use(new GoogleStrategy({
    clientID: process.env['Client_ID'],
    clientSecret: process.env['Client_Secret'],
    callbackURL: "http://localhost:3000/auth/google/callback"
}, async(accessToken, refreshToken, profile, done) => {
    try {
            const email = profile.emails?.[0]?.value || "";
            const displayPicture = profile.photos?.[0]?.value || "https://www.shutterstock.com/image-vector/avatar-gender-neutral-silhouette-vector-600nw-2470054311.jpg";
            const userRef = db.collection("users").doc(profile.id);
            const userSnap = await userRef.get();

            let userData;

            if (!userSnap.exists) 
                {
                    userData = {
                        id: profile.id,
                        displayName: profile.displayName,
                        displayPicture: displayPicture,
                        email: email,
                        role: "user",
                        totp: {
                            enabled: false,
                            secret: null,
                        },
                        createdAt: new Date().toISOString()
                    };
                    await userRef.set(userData);
                    console.log(` Created new user: ${email}`);
                } 
            else 
                {
                    userData = userSnap.data();
                    console.log(` Returning user: ${email}`);
                }

            return done(null, userData);
        } 
    catch (err) 
    {
        console.error("Error handling Google login:", err);
        return done(err, null);
    }
}));


passport.serializeUser((user, done) => {done(null, user);}); // stores user obj in session cookie
passport.deserializeUser((user, done) => {done(null, user);});





// Frontend Starting point
app.use(express.static(path.join(__dirname, "../frontend/public")));





// Google login trigger
app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

// Google login continuation
app.get("/auth/google/callback", (req, res, next) => {
    passport.authenticate("google", async (err, user) => {
        if (err || !user) return res.redirect("/index.html");

        // Store temporarily (not authenticated yet)
        req.session.tempUser = user;

        // directly authenticate if 2FA not enabled
        if (!user.totp.enabled) {
            return req.login(user, err => {
                if (err) throw err;

                delete req.session.tempUser;

                // Redirect based on role
                if (user.role === "admin" || user.role === "user") {
                    if(user.role !== "admin"){return res.render('dashboard', {
                        title: "My Dashboard",
                        currentPage: "dashboard",
                        user: {name: user.displayName, notificationCount: 3, profileImgUrl: `${user.displayPicture}`},
                        stats: statsData,
                        courses: coursesData,
                        assignments: assignmentsData
                    });}
                    else
                        {return res.render('dashboard-t', {
                        title: "Teacher Dashboard",
                        currentPage: "dashboard",
                        user: {name: user.displayName, assignmentsToGrade: 17, notificationCount: 5, profileImgUrl: `${user.displayPicture}`},
                        stats: statsData_t,
                        classes: classData,
                        gradingQueue: gradingData
                    });}
                }
            });
        }
        // Redirect to 2FA input page
        return res.redirect("/totp.html");
    })(req, res, next);
});



app.post("/verify-totp", (req, res) => {
    
    const code = `${req.body.otp1}${req.body.otp2}${req.body.otp3}${req.body.otp4}${req.body.otp5}${req.body.otp6}`;
    const tempUser = req.session.tempUser;

    if (!tempUser) {
        return res.redirect("/index.html");
    }
    // Verify TOTP code
    const verified = Totp.validate({ passcode: `${code}`, secret: `${tempUser.totp.secret}` });
    
    if (!verified) {
        return res.redirect("/2fa.html?error=invalid");
    }
    else
        {
        // TOTP verified, authenticate user
        req.login(tempUser, err => {
            if (err) {
                console.error("Login error:", err);
                return res.redirect("/index.html"); 
            }

            // Cleanup temp session
            delete req.session.tempUser;

            // Redirect to dashboard based on role
            if (tempUser.role === "admin" || tempUser.role === "user") {
                if(tempUser.role !== "admin")
                    {return res.render('dashboard', {
                    title: "My Dashboard",
                    currentPage: "dashboard",
                    user: {name: tempUser.displayName, notificationCount: 3, profileImgUrl: `${tempUser.displayPicture}`},
                    stats: statsData,
                    courses: coursesData,
                    assignments: assignmentsData
                });}

                else{return res.render('dashboard-t', {
                    title: "Teacher Dashboard",
                    currentPage: "dashboard",
                    user: {name: tempUser.displayName, assignmentsToGrade: 17, notificationCount: 5, profileImgUrl: `${tempUser.displayPicture}`},
                    stats: statsData_t,
                    classes: classData,
                    gradingQueue: gradingData
                });}
            }
        });
    }
});



app.get("/2fa/generate", async (req, res) => {
    if (!req.isAuthenticated()) {
        return res.redirect("/index.html");
    }
    const user = req.user;

    const key = Totp.generateKey({ issuer: "SSO/Demo/Proj", user: `${user.email}` });
    
    const secret = key.secret;
    const url = key.url;
    const qr = await QRCode.toDataURL(url, {errorCorrectionLevel: 'H'});
    
    user.totp.tempsecret = secret;

    res.json({ qrCodeUrl: qr, secret: secret.match(/.{1,4}/g).join(' '), });
});


app.post("/2fa/verify", async (req, res) => {
    if (!req.isAuthenticated()) {
        return res.redirect("/index.html");
    }
    const sec = req.user.totp.tempsecret; 
    const code = req.body.otp;
    const valid = Totp.validate({ passcode: `${code}`, secret: `${sec}` });
    if (valid) 
        {
            // Enable TOTP for user
            try {
                await db.collection("users").doc(req.user.id).update({ totp: {enabled: true, secret: sec} });
                req.user.totp = {enabled: true, secret: sec};
                delete req.user.totp.tempsecret;
                res.json({ success: true, verified: valid });   
            } 
            catch (error) {
                console.log('2FA Error:', error);
                res.status(500).json({ success: false, error: "2FA process Failure" });
            }
        }
});

app.post("/2fa/disable", async (req, res) => {
    if (!req.isAuthenticated()) {
        return res.redirect("/index.html");
    }

    try {
        await db.collection("users").doc(req.user.id).update({ totp: { enabled: false, secret: null } });
        req.user.totp = { enabled: false, secret: null };
        return res.json({ success: true, disabled: true });
    } 
    catch (err) {
        console.error("Error disabling 2FA:", err);
        return res.status(500).json({ success: false, error: "Failed to disable 2FA" });
    }
});



app.get("/settings", (req, res) => {
    if (!req.isAuthenticated()) {
        return res.redirect("/index.html");
    }

    res.render('settings', {
        title: "Settings",
        currentPage: "settings",
        user: req.user
    });
});

app.get("/dashboard", (req, res) => {
    if (!req.isAuthenticated()) {
        return res.redirect("/index.html");
    }
    const user = req.user;
    if (user.role === "admin" || user.role === "user") {
        if(user.role !== "admin")
            {return res.render('dashboard', {
            title: "My Dashboard",
            currentPage: "dashboard",
            user: {name: user.displayName, notificationCount: 3, profileImgUrl: `${user.displayPicture}`},
            stats: statsData,
            courses: coursesData,
            assignments: assignmentsData
        });}

        else{return res.render('dashboard-t', {
            title: "Teacher Dashboard",
            currentPage: "dashboard",
            user: {name: user.displayName, assignmentsToGrade: 17, notificationCount: 5, profileImgUrl: `${user.displayPicture}`},
            stats: statsData_t,
            classes: classData,
            gradingQueue: gradingData
        });}
    }
});

// Logout call
app.get("/logout", (req, res) => {
  req.logout(() => {
    res.redirect("/index.html");
  });
});










const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Server running on port", PORT));












// Dummy data for rendering dashboards


    const userData = {
        name: "Alex",
        notificationCount: 3,
        profileImgUrl: "https://source.unsplash.com/100x100/?portrait,student"
    };

    const statsData = {
        activeCourses: 4,
        assignmentsDue: 3,
        recentGrade: "A-",
        upcomingEvents: 2
    };

    const coursesData = [
        {
            title: "MATH-101: Introduction to Calculus",
            professor: "Prof. Evans",
            progress: 75,
            progressColor: "", // Bootstrap default
            imageUrl: "https://static.vecteezy.com/system/resources/thumbnails/009/377/766/small_2x/3d-book-icon-with-transparent-background-free-png.png"
        },
        {
            title: "HIST-202: Modern World History",
            professor: "Dr. Chen",
            progress: 40,
            progressColor: "bg-success",
            imageUrl: "https://static.vecteezy.com/system/resources/thumbnails/009/377/766/small_2x/3d-book-icon-with-transparent-background-free-png.png"
        },
        {
            title: "CHEM-100: General Chemistry",
            professor: "Prof. Patel",
            progress: 60,
            progressColor: "bg-warning",
            imageUrl: "https://static.vecteezy.com/system/resources/thumbnails/009/377/766/small_2x/3d-book-icon-with-transparent-background-free-png.png"
        }
    ];

    const assignmentsData = [
        {
            title: "Calculus Homework 5",
            courseCode: "MATH-101",
            dueDate: "Due Oct 30",
            badgeClass: "bg-danger-subtle text-danger-emphasis"
        },
        {
            title: "History Essay Prompt",
            courseCode: "HIST-202",
            dueDate: "Due Nov 01",
            badgeClass: "bg-warning-subtle text-warning-emphasis"
        },
        {
            title: "Lab Report 2",
            courseCode: "CHEM-100",
            dueDate: "Due Nov 03",
            badgeClass: "bg-warning-subtle text-warning-emphasis"
        }
    ];

    // res.render('dashboard', {
    //     title: "My Dashboard",
    //     currentPage: "dashboard", // For the active sidebar link
    //     user: userData,
    //     stats: statsData,
    //     courses: coursesData,
    //     assignments: assignmentsData
    // });


    

    const teacherData = {
        name: "Prof. Davis",
        assignmentsToGrade: 17,
        notificationCount: 5,
        profileImgUrl: "https://source.unsplash.com/100x100/?portrait,professor"
    };

    const statsData_t = {
        totalStudents: 124,
        classesTaught: 4,
        needsGrading: 17, // This matches the user.assignmentsToGrade
        meetingsToday: 2
    };

    const classData = [
        {
            id: "phys-301",
            title: "PHYS-301: Advanced Mechanics",
            studentCount: 32,
            imageUrl: "https://source.unsplash.com/400x300/?physics,science"
        },
        {
            id: "lit-210",
            title: "LIT-210: Shakespearean Tragedy",
            studentCount: 28,
            imageUrl: "https://source.unsplash.com/400x300/?literature,books"
        },
        {
            id: "cs-450",
            title: "CS-450: Data Structures & Algorithms",
            studentCount: 45,
            imageUrl: "https://source.unsplash.com/400x300/?computer,code"
        },
        {
            id: "phil-100",
            title: "PHIL-100: Introduction to Logic",
            studentCount: 19,
            imageUrl: "https://source.unsplash.com/400x300/?philosophy,statue"
        }
    ];

    const gradingData = [
        {
            title: "Data Structures: Quiz 3",
            courseCode: "CS-450",
            status: "12",
            badgeClass: "bg-danger"
        },
        {
            title: "Mechanics: Homework 8",
            courseCode: "PHYS-301",
            status: "5",
            badgeClass: "bg-danger"
        },
        {
            title: "Hamlet Essay: Final Draft",
            courseCode: "LIT-210",
            status: "Due Friday",
            badgeClass: "bg-secondary-subtle text-secondary-emphasis"
        },
        {
            title: "Logic: Midterm Exam",
            courseCode: "PHIL-100",
            status: "All Graded",
            badgeClass: "bg-success-subtle text-success-emphasis"
        },
        {
            title: "Mechanics: Lab Report 4",
            courseCode: "PHYS-301",
            status: "Due Sunday",
            badgeClass: "bg-secondary-subtle text-secondary-emphasis"
        }
    ];

    // res.render('teacher-dashboard', {
    //     title: "Teacher Dashboard",
    //     currentPage: "dashboard", // For the active sidebar link
    //     user: teacherData,
    //     stats: statsData,
    //     classes: classData,
    //     gradingQueue: gradingData

    // });
