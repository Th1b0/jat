<?php

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;

use Slim\Factory\AppFactory;
use DI\Container;
use Slim\Views\Twig;
use Slim\Views\TwigMiddleware;
use Twig\Loader\FilesystemLoader;

require __DIR__ . '/../vendor/autoload.php';

// Create Container using PHP-DI
$container = new Container();

// Set container to create App with on AppFactory
AppFactory::setContainer($container);

// Create App
$app = AppFactory::create();

// Configure Twig
$container->set('view', function () {
    $loader = new FilesystemLoader(__DIR__ . '/../templates');
    $twig = new Twig($loader, ['cache' => false]);
    return $twig;
});

// Add Twig-View Middleware
$app->add(TwigMiddleware::createFromContainer($app, 'view'));

// Add Middleware to handle JSON
$app->addBodyParsingMiddleware();

// Function to handle CRUD operations
function executeQuery($db, $query, $params = [], $isSelect = false)
{
    try {
        $stmt = $db->prepare($query);
        $stmt->execute($params);

        if ($isSelect) {
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
        } else {
            return $stmt->rowCount();
        }
    } catch (PDOException $e) {
        error_log($e->getMessage());
        return false;
    }
}

function  authenticate($db, $request)
{
    $cookies = $request->getCookieParams();
    $sessionId = $cookies['session_id'] ?? null;

    if (!$sessionId) {

        return false;
    }

    $queryCheckSession = 'SELECT userid FROM "Session" WHERE id = :id AND valid = true';
    $paramsCheckSession = ['id' => $sessionId];
    $session = executeQuery($db, $queryCheckSession, $paramsCheckSession, true);

    if (empty($session[0]['userid'])) {
        return false;
    } else {
        return $session[0]['userid'];
    }
};

function authorize($db, $id)
{
    // Query to fetch the role of the user
    $queryCheckRole = 'SELECT "role" FROM "User" WHERE id = :id';
    $paramsCheckRole = ['id' => $id];
    $user = executeQuery($db, $queryCheckRole, $paramsCheckRole, true);

    // Check if the user exists and has an admin role
    if (!empty($user) && $user[0]['role'] === 'admin') {
        return true; // Return true if the user is an admin
    } else {
        return false; // Return false if the user is not an admin or doesn't exist
    }
}

// Database Configuration
$container->set('db', function () {
    $host = 'localhost'; // Change to your host address
    $port = '5433'; // Change to your desired port number
    $dbname = 'jat';
    $user = 'thibo';
    $pass = 'thibo';
    $dsn = "pgsql:host=$host;port=$port;dbname=$dbname"; // Include the port in the DSN

    $pdo = new PDO($dsn, $user, $pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    return $pdo;
});

// Define named route
$app->get('/login', function (Request $request, Response $response, $args) {
    $valid = authenticate($this->get('db'), $request);
    if ($valid) {
        $view = $this->get('view');
        return $response->withHeader('Location', '/dashboard')->withStatus(302);
    }

    $view = $this->get('view');
    return $view->render($response, 'login.twig');
});

$app->post('/auth/login', function (Request $request, Response $response, $args) {
   

    $data = $request->getParsedBody();

    // If the body is not parsed, decode JSON manually
    if (empty($data)) {
        $bodyContent = $request->getBody()->getContents();
        $data = json_decode($bodyContent, true);
    }

    // Check if all required fields are present
    if (isset($data['email']) && isset($data['password'])) {
        $db = $this->get('db');

        // Fetch the user by email
        $queryFetchUser = 'SELECT id, email, hash FROM "User" WHERE email = :email';
        $paramsFetchUser = ['email' => $data['email']];
        $user = executeQuery($db, $queryFetchUser, $paramsFetchUser, true);

        if (!empty($user) && password_verify($data['password'], $user[0]['hash'])) {
            // Password is correct
            $userId = $user[0]['id'];

            // Create a new session for the user
            $queryCreateSession = 'INSERT INTO "Session" (userId, valid) VALUES (:userId, :valid) RETURNING id';
            $paramsCreateSession = ['userId' => $userId, 'valid' => true];

            try {
                $stmt = $db->prepare($queryCreateSession);
                $stmt->execute($paramsCreateSession);
                $sessionId = $stmt->fetchColumn(); // Get the session ID

                if ($sessionId) {
                    // Set the session ID as a cookie
                    setcookie('session_id', $sessionId, [
                        'expires' => time() + (86400 * 30), // 30 days
                        'path' => '/',
                        'secure' => true,
                        'httponly' => true,
                        'samesite' => 'Strict'
                    ]);

                    $response->getBody()->write(json_encode([
                        'status' => 'success',
                        'message' => 'User is valid and session created.',
                    ]));
                    return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
                } else {
                    $response->getBody()->write(json_encode([
                        'status' => 'error',
                        'message' => 'Failed to create session.',
                    ]));
                    return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
                }
            } catch (PDOException $e) {
                $response->getBody()->write(json_encode([
                    'status' => 'error',
                    'message' => 'Database error: ' . $e->getMessage(),
                ]));
                return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
            }
        } else {
            // Invalid credentials
            $response->getBody()->write(json_encode([
                'status' => 'error',
                'message' => 'Invalid email or password.',
            ]));
            return $response->withHeader('Content-Type', 'application/json')->withStatus(401);
        }
    } else {
        // Missing fields
        $response->getBody()->write(json_encode([
            'status' => 'error',
            'message' => 'Required fields are missing.',
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
    }
});


$app->post('/auth/update', function (Request $request, Response $response, $args) {
    $valid = authenticate($this->get('db'), $request);

    if (!$valid) {
        $response->getBody()->write(json_encode([
            'status' => 'error',
            'message' => 'Not authenticated.',
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
    }

    $data = $request->getParsedBody();

    // If the body is not parsed, decode JSON manually
    if (empty($data)) {
        $bodyContent = $request->getBody()->getContents();
        $data = json_decode($bodyContent, true);
    }

    // Check if all required fields are present
    if (isset($data['password'])) {
        $db = $this->get('db');

        // Hash the new password
        $hashedPassword = password_hash($data['password'], PASSWORD_DEFAULT);

        // Update the user's password in the database
        $queryUpdatePassword = 'UPDATE "User" SET hash = :hashedPassword WHERE id = :userId';
        $paramsUpdatePassword = ['hashedPassword' => $hashedPassword, 'userId' => $valid];
        executeQuery($db, $queryUpdatePassword, $paramsUpdatePassword);

        $queryUpdateSession = 'UPDATE "Session" SET valid = false WHERE userid = :userId';
        $paramsUpdateSession = ['userId' => $valid];
        executeQuery($db, $queryUpdateSession, $paramsUpdateSession);

        // Return success response
        $response->getBody()->write(json_encode([
            'status' => 'success',
            'message' => 'Password updated successfully.',
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    } else {
        // Return error response if required fields are missing
        $response->getBody()->write(json_encode([
            'status' => 'error',
            'message' => 'Missing required fields.',
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
    }
});


$app->post('/auth/logout', function (Request $request, Response $response, $args) {
    $valid = authenticate($this->get('db'), $request);

    if (!$valid) {
        $response->getBody()->write(json_encode([
            'status' => 'error',
            'message' => 'Not authenticated.',
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
    }

    $data = $request->getParsedBody();

    // If the body is not parsed, decode JSON manually
    if (empty($data)) {
        $bodyContent = $request->getBody()->getContents();
        $data = json_decode($bodyContent, true);
    }

    // Check if all required fields are present
   
        $db = $this->get('db');

        // Set valid to false for the user's session in the Session table
        $queryUpdateSession = 'UPDATE "Session" SET valid = false WHERE userid = :userId';
        $paramsUpdateSession = ['userId' => $valid];
        executeQuery($db, $queryUpdateSession, $paramsUpdateSession);

        // Return success response
        $response->getBody()->write(json_encode([
            'status' => 'success',
            'message' => 'Logged out successfully.',
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
   
});




$app->get('/register/{id}', function (Request $request, Response $response, $args) {
    
    $valid = authenticate($this->get('db'), $request);
    if ($valid) {
        $view = $this->get('view');
        return $response->withHeader('Location', '/dashboard')->withStatus(302);
    }
    $view = $this->get('view');
    return $view->render($response, 'register.twig');
});

$app->post('/auth/register/{id}', function (Request $request, Response $response, $args) {
   
    $userId = $args['id']; // Retrieve the {id} from the URL
    $data = $request->getParsedBody();

    // If the body is not parsed, decode JSON manually
    if (empty($data)) {
        $bodyContent = $request->getBody()->getContents();
        $data = json_decode($bodyContent, true);
    }

    // Check if all required fields are present
    if (isset($data['email']) && isset($data['password'])) {
        $db = $this->get('db');

        // Check if the provided ID is a valid Uri ID
        $queryCheckUri = 'SELECT userid FROM "Uri" WHERE id = :id AND valid = true';
        $paramsCheckUri = ['id' => $userId];

        $validUri = executeQuery($db, $queryCheckUri, $paramsCheckUri, true);

        if (!$validUri[0]["userid"]) {
            $response->getBody()->write(json_encode([
                'status' => 'success',
                'message' => 'Invalid Uri Id',
                'userId' => $validUri[0]["userid"],
            ]));
            return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
        }



        // Proceed with updating the user's email if it's not already taken
        $queryUpdateEmail = 'UPDATE "User" SET email = :email, hash = :hash WHERE id = :id';
        $paramsUpdateEmail = ['id' => $validUri[0]["userid"], 'email' => $data['email'], 'hash' => password_hash($data['password'], PASSWORD_DEFAULT)];

        try {
            $result = executeQuery($db, $queryUpdateEmail, $paramsUpdateEmail);
            if ($result) {
                // Update the valid column of the Uri associated with the user ID to false
                $queryUpdateUri = 'UPDATE "Uri" SET valid = false WHERE id = :id';
                $paramsUpdateUri = ['id' => $userId];
                executeQuery($db, $queryUpdateUri, $paramsUpdateUri);

                $response->getBody()->write(json_encode([
                    'status' => 'success',
                    'message' => 'User updated successfully. Uri marked as invalid.',
                ]));
                return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
            } else {
                $response->getBody()->write(json_encode([
                    'status' => 'error',
                    'message' => 'Failed to update user.',
                ]));
                return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
            }
        } catch (PDOException $e) {
            $response->getBody()->write(json_encode([
                'status' => 'error',
                'message' => 'Database error: ' . $e->getMessage(),
            ]));
            return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
        }
    } else {
        $response->getBody()->write(json_encode([
            'status' => 'error',
            'message' => 'Required fields are missing.',
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
    }
});

$app->post('/uri/create', function (Request $request, Response $response, $args) {


    $valid = authenticate($this->get('db'), $request);

    if (!$valid) {
        $response->getBody()->write(json_encode([
            'status' => 'error',
            'message' => 'Not authenticated.',
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
    }

    $auhtorized = authorize($this->get('db'), $valid);

    if (!$auhtorized) {
        $response->getBody()->write(json_encode([
            'status' => 'error',
            'message' => 'Not auhtorized.',
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
    }

    $data = $request->getParsedBody();

    // If the body is not parsed, decode JSON manually
    if (empty($data)) {
        $bodyContent = $request->getBody()->getContents();
        $data = json_decode($bodyContent, true);
    }

    // Check if all required fields are present
    if (isset($data['surname']) && isset($data['name'])) {
        $db = $this->get('db');

        try {
            $db->beginTransaction();

            // Proceed with inserting the user into the database
            $queryInsertUser = 'INSERT INTO "User" (surname, name) VALUES (:surname, :name) RETURNING id';
            $paramsInsertUser = ['surname' => $data['surname'], 'name' => $data['name']];

            $stmt = $db->prepare($queryInsertUser);
            $stmt->execute($paramsInsertUser);
            $userId = $stmt->fetchColumn(); // Retrieve the userId from the inserted row

            // Insert into Uri table
            $queryInsertUri = 'INSERT INTO "Uri" (userId, valid) VALUES (:userId, :valid)';
            $paramsInsertUri = ['userId' => $userId, 'valid' => true];
            $stmt = $db->prepare($queryInsertUri);
            $stmt->execute($paramsInsertUri);

            $db->commit();

            $response->getBody()->write(json_encode([
                'status' => 'success',
                'message' => 'User and Uri inserted successfully.',
                'userId' => $userId, // Include the userId in the response
            ]));
            return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
        } catch (PDOException $e) {
            $db->rollBack();

            $response->getBody()->write(json_encode([
                'status' => 'error',
                'message' => 'Database error: ' . $e->getMessage(),
            ]));
            return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
        }
    } else {
        $response->getBody()->write(json_encode([
            'status' => 'error',
            'message' => 'Required fields are missing.',
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
    }
});


$app->get('/dashboard', function (Request $request, Response $response, $args) {
    $valid = authenticate($this->get('db'), $request);

    if (!$valid) {
        $response->getBody()->write(json_encode([
            'status' => 'error',
            'message' => 'Not auhtorized.',
        ]));
        return $response->withHeader('Location', '/report')->withStatus(302);
    }
    $auhtorized = authorize($this->get('db'), $valid);

    if (!$auhtorized) {
        $response->getBody()->write(json_encode([
            'status' => 'error',
            'message' => 'Not auhtorized.',
        ]));
        return $response->withHeader('Location', '/report')->withStatus(302);
    }
    $db = $this->get('db');
    $valid = authenticate($db, $request);

    if ($valid) {
        // Fetch the counts for each status
        $chartData = [
            executeQuery($db, 'SELECT COUNT(*) as count FROM "Problem" WHERE status = ?', ['active'], true)[0]['count'],
            executeQuery($db, 'SELECT COUNT(*) as count FROM "Problem" WHERE status = ?', ['closed'], true)[0]['count'],
            executeQuery($db, 'SELECT COUNT(*) as count FROM "Problem" WHERE status = ?', ['halted'], true)[0]['count']
        ];

        // Query for problems created today
        $problemsCreatedToday = executeQuery($db, 'SELECT COUNT(*) as count FROM "Problem" WHERE status = ? AND DATE(created_at) = CURRENT_DATE', ['active'], true)[0]['count'];

        // Query for problems resolved today
        $problemsResolvedToday = executeQuery($db, 'SELECT COUNT(*) as count FROM "Problem" WHERE status = ? AND DATE(closed_at) = CURRENT_DATE', ['closed'], true)[0]['count'];

        // Fetch the counts for each category
        $categoryCounts = [
            'Hardware' => executeQuery($db, 'SELECT COUNT(*) as count FROM "Problem" WHERE category = ?', ['Hardware'], true)[0]['count'],
            'Microsoft' => executeQuery($db, 'SELECT COUNT(*) as count FROM "Problem" WHERE category = ?', ['Microsoft'], true)[0]['count'],
            'Smartschool' => executeQuery($db, 'SELECT COUNT(*) as count FROM "Problem" WHERE category = ?', ['Smartschool'], true)[0]['count'],
            'Iddink' => executeQuery($db, 'SELECT COUNT(*) as count FROM "Problem" WHERE category = ?', ['Iddink'], true)[0]['count'],
            'Software' => executeQuery($db, 'SELECT COUNT(*) as count FROM "Problem" WHERE category = ?', ['Software'], true)[0]['count'],
        ];

        $view = $this->get('view');
        return $view->render($response, 'dashboard.twig', [
            'chartData' => $chartData,
            'problemsCreatedToday' => $problemsCreatedToday,
            'problemsResolvedToday' => $problemsResolvedToday,
            'categoryCounts' => $categoryCounts,
        ]);
    } else {
        return $response->withHeader('Location', '/login')->withStatus(302);
    }
});



$app->get('/report', function (Request $request, Response $response, $args) {
    $valid = authenticate($this->get('db'), $request);
    if ($valid) {
        $view = $this->get('view');
        return $view->render($response, 'report.twig');
    } else {
        return $response->withHeader('Location', '/login')->withStatus(302);
    }
});

$app->post('/problem/create', function (Request $request, Response $response, $args) {
    $valid = authenticate($this->get('db'), $request);

    if ($valid) {
        $data = $request->getParsedBody();

        
        if (empty($data)) {
            $bodyContent = $request->getBody()->getContents();
            $data = json_decode($bodyContent, true);
        }

        // Check if all required fields are present
        if (isset($data['name']) && isset($data['description']) && isset($data['category'])) {
            $db = $this->get('db');

            try {
                $db->beginTransaction();

                // Proceed with inserting the user into the database
                $queryInsertUser = 'INSERT INTO "Problem" (name, description, category, status, creatorid) VALUES (:name, :description, :category, :status, :creatorid)';
                $paramsInsertUser = [
                    'name' => $data['name'],
                    'description' => $data['description'],
                    'category' => $data['category'],  // Ensure this matches the third position in the VALUES clause
                    'status' => "active",             // Ensure this matches the fourth position in the VALUES clause
                    'creatorid' => $valid
                ];
                

                $stmt = $db->prepare($queryInsertUser);
                $stmt->execute($paramsInsertUser);

                $db->commit();

                $response->getBody()->write(json_encode([
                    'status' => 'success',
                    'message' => 'Problem created...',

                ]));
                return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
            } catch (PDOException $e) {
                $db->rollBack();

                $response->getBody()->write(json_encode([
                    'status' => 'error',
                    'message' => 'Database error: ' . $e->getMessage() . $valid,
                ]));
                return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
            }
        } else {
            $response->getBody()->write(json_encode([
                'status' => 'error',
                'message' => 'Required fields are missing.',
            ]));
            return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
        }
    } else {
        return $response->withHeader('Location', '/login')->withStatus(302);
    }
});

$app->post('/problem/update', function (Request $request, Response $response, $args) {
    $valid = authenticate($this->get('db'), $request);

    if ($valid) {
        $data = $request->getParsedBody();

        if (empty($data)) {
            $bodyContent = $request->getBody()->getContents();
            $data = json_decode($bodyContent, true);
        }

        if (!isset($data['id'])) {
            $response->getBody()->write(json_encode([
                'status' => 'error',
                'message' => 'Problem ID is required.',
            ]));
            return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
        }

        if (!isset($data['status'])) {
            $response->getBody()->write(json_encode([
                'status' => 'error',
                'message' => 'Status is required.',
            ]));
            return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
        }

        $db = $this->get('db');
        $problemId = $data['id'];
        $status = $data['status'];

        $updateQuery = 'UPDATE "Problem" SET status = :status WHERE id = :id';
        $params = [
            'status' => $status,
            'id' => $problemId,
        ];

        try {
            $db->beginTransaction();
            $stmt = $db->prepare($updateQuery);
            $stmt->execute($params);
            $db->commit();

            $response->getBody()->write(json_encode([
                'status' => 'success',
                'message' => 'Problem status updated successfully.',
            ]));
            return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
        } catch (PDOException $e) {
            $db->rollBack();

            $response->getBody()->write(json_encode([
                'status' => 'error',
                'message' => 'Database error: ' . $e->getMessage(),
            ]));
            return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
        }
    } else {
        return $response->withHeader('Location', '/login')->withStatus(302);
    }
});


$app->get('/problems', function (Request $request, Response $response, $args) {
    $valid = authenticate($this->get('db'), $request);

    
    if ($valid) {
        $db = $this->get('db');

        $auhtorized = authorize($this->get('db'), $valid);

        if (!$auhtorized) {
            $response->getBody()->write(json_encode([
                'status' => 'error',
                'message' => 'Not auhtorized.',
            ]));
            return $response->withHeader('Location', '/report')->withStatus(302);
        }
        // Fetch problems with proper field names
        $problems = executeQuery($db, 'SELECT "id", "name", "createdat", "status","description","category" FROM "Problem"', [], true);
        $totalProblems = count($problems);
        // Pass the fetched data to Twig
        $view = $this->get('view');
        return $view->render($response, 'problems.twig', [
            'problems' => $problems,
            'totalProblems' => $totalProblems,
        ]);
    } else {
        return $response->withHeader('Location', '/login')->withStatus(302);
    }
});

$app->get('/settings', function (Request $request, Response $response, $args) {
    $valid = authenticate($this->get('db'), $request);
    if ($valid) {
        $auhtorized = authorize($this->get('db'), $valid);

        if (!$auhtorized) {
            $view = $this->get('view');
        return $view->render($response, 'setting.twig', [
        ]);
            
        }
        $db = $this->get('db');
        $query = 'SELECT u."id" as user_id, u."surname", u."name", ur."id" as uri_id
                  FROM "User" u
                  JOIN "Uri" ur ON u."id" = ur."userid"
                  WHERE valid = true';
        $usersWithoutEmail = executeQuery($db, $query, [], true);

        $tableMarkup = '
        <div class="center">
            <h4 class="inlog-tag">Add User</h4>
        </div>
        <hr class="gray">
        <form id="addUserForm">
            <div class="row">
                <div class="col-md-6">
                    <div class="form-group">
                        <label for="surname">Firt name</label>
                        <input type="text" class="form-control" id="surname" name="surname">
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="form-group">
                        <label for="name">Name</label>
                        <input type="text" class="form-control" id="name" name="name">
                    </div>
                </div>
                
            </div>
            <br>
            
            <div class="form-group">
                <button type="submit" class="btn btn-primary btn-block">Add User</button>
            </div>
        </form>
        ';

        // Render the Twig template
        $view = $this->get('view');
        return $view->render($response, 'setting.twig', [
            'tableMarkup' => $tableMarkup,
            'users' => $usersWithoutEmail,
        ]);
    } else {
        return $response->withHeader('Location', '/login')->withStatus(302);
    }
});





// Serve static files
$app->get('/static/{file}', function (Request $request, Response $response, $args) {
    $filePath = __DIR__ . '/../public/' . $args['file'];
    if (!file_exists($filePath)) {
        return $response->withStatus(404);
    }

    $mimeType = mime_content_type($filePath);
    $response = $response->withHeader('Content-Type', $mimeType);
    $response->getBody()->write(file_get_contents($filePath));
    return $response;
});

// Run App
$app->run();
