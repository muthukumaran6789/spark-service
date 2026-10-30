require('dotenv').config();

const express = require('express');
const cors = require('cors');
const swaggerUi = require('swagger-ui-express');
const openapiSpec = require('./openapi.json');
const { randomBytes, randomUUID, scrypt: scryptCallback } = require('node:crypto');
const { promisify } = require('node:util');
const { assertAuthConfig, authenticate, createAuthRouter, requireRoles } = require('./auth');
const { hasCosmosCredentials, initializeCosmos } = require('./cosmos');
const app = express();
const PORT = process.env.PORT || 3000;
const scrypt = promisify(scryptCallback);

let projectsContainer;
let usersContainer;
let sessionsContainer;
let applicationsContainer;

// Built-in middleware to handle JSON data
app.use(cors());
app.use(express.json());
app.get('/openapi.json', (req, res) => res.json(openapiSpec));
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(openapiSpec, {
  swaggerOptions: { validatorUrl: null },
}));
app.use('/api/auth', createAuthRouter(express, () => (
  usersContainer && sessionsContainer
    ? { users: usersContainer, sessions: sessionsContainer }
    : null
)));

// A basic GET route
app.get('/', (req, res) => {
  res.send('Hello, Express server is running successfully!');
});

function toPublicUser(user) {
  return {
    userId: user.userId,
    email: user.email,
    displayName: user.displayName,
    role: user.role,
    status: user.status,
    createdAt: user.createdAt,
  };
}

// Return the authenticated user's profile, using identity claims from the verified access token.
app.get('/api/user', authenticate, async (req, res) => {
  if (!usersContainer) {
    return res.status(503).json({ error: 'Cosmos DB is not configured.' });
  }

  try {
    let user;
    if (req.auth.emailKey) {
      ({ resource: user } = await usersContainer.item('profile', req.auth.emailKey).read());
    } else {
      // Compatibility for access tokens issued before emailKey was added as a claim.
      const { resources } = await usersContainer.items.query({
        query: 'SELECT * FROM c WHERE c.userId = @userId',
        parameters: [{ name: '@userId', value: req.auth.userId }],
      }).fetchAll();
      [user] = resources;
    }

    if (!user || user.userId !== req.auth.userId) {
      return res.status(404).json({ error: 'User not found.' });
    }
    return res.json(toPublicUser(user));
  } catch (error) {
    if (error.code === 404 || error.statusCode === 404) {
      return res.status(404).json({ error: 'User not found.' });
    }
    console.error('Failed to read authenticated user:', error.message);
    return res.status(500).json({ error: 'Unable to read user.' });
  }
});

function authorizeRegistrationRole(req, res, next) {
  const role = req.body?.role;
  if (!['applicant', 'manager', 'superAdmin'].includes(role)) {
    return res.status(400).json({ error: 'Role must be applicant, manager, or superAdmin.' });
  }
  if (role === 'applicant') return next();

  return authenticate(req, res, () => requireRoles('superAdmin')(req, res, next));
}

async function getAuthenticatedUser(auth) {
  try {
    if (auth.emailKey) {
      const { resource } = await usersContainer.item('profile', auth.emailKey).read();
      return resource;
    }

    const { resources } = await usersContainer.items.query({
      query: 'SELECT * FROM c WHERE c.userId = @userId',
      parameters: [{ name: '@userId', value: auth.userId }],
    }).fetchAll();
    return resources[0];
  } catch (error) {
    if (error.code === 404 || error.statusCode === 404) return undefined;
    throw error;
  }
}

function toProjectResponse(project) {
  return {
    id: project.id,
    projectId: project.projectId,
    title: project.title ?? null,
    projectName: project.projectName ?? null,
    duration: project.duration ?? null,
    description: project.description ?? null,
    status: project.status ?? 'open',
    manager: project.manager ?? null,
    createdAt: project.createdAt,
  };
}

function toApplicationResponse(application) {
  return {
    id: application.id,
    projectId: application.projectId,
    userId: application.userId,
    applicant: application.applicant,
    message: application.message,
    status: application.status,
    appliedAt: application.appliedAt,
    statusUpdatedAt: application.statusUpdatedAt,
    statusUpdatedBy: application.statusUpdatedBy,
  };
}

// Read one user by email using the Users container's partition key.
app.get('/api/users/all', authenticate, requireRoles('superAdmin'), async (req, res) => {
  if (!usersContainer) {
    return res.status(503).json({ error: 'Cosmos DB is not configured.' });
  }

  try {
    // Project only public profile fields so credential data never leaves Cosmos.
    const { resources } = await usersContainer.items.query({
      query: `SELECT VALUE {
        "userId": c.userId,
        "email": c.email,
        "displayName": c.displayName,
        "role": c.role,
        "status": c.status,
        "createdAt": c.createdAt
      } FROM c`,
    }).fetchAll();
    return res.json(resources);
  } catch (error) {
    console.error('Failed to list users:', error.message);
    return res.status(500).json({ error: 'Unable to list users.' });
  }
});

app.get('/api/users', authenticate, async (req, res) => {
  if (!usersContainer) {
    return res.status(503).json({ error: 'Cosmos DB is not configured.' });
  }

  const email = typeof req.query.email === 'string' ? req.query.email.trim().toLowerCase() : '';
  if (!email) {
    return res.status(400).json({ error: 'Provide an email query parameter.' });
  }

  try {
    const { resource } = await usersContainer.item('profile', email).read();
    if (!resource) {
      return res.status(404).json({ error: 'User not found.' });
    }
    if (resource.userId !== req.auth.userId && req.auth.role !== 'superAdmin') {
      return res.status(403).json({ error: 'You can only read your own user profile.' });
    }
    return res.json(toPublicUser(resource));
  } catch (error) {
    if (error.code === 404 || error.statusCode === 404) {
      return res.status(404).json({ error: 'User not found.' });
    }
    console.error('Failed to read user:', error.message);
    return res.status(500).json({ error: 'Unable to read user.' });
  }
});

// Register an applicant. The client cannot assign privileged roles or supply a password hash.
app.post('/api/users', authorizeRegistrationRole, async (req, res) => {
  if (!usersContainer) {
    return res.status(503).json({ error: 'Cosmos DB is not configured.' });
  }

  const { email: rawEmail, displayName, password, role } = req.body ?? {};
  const email = typeof rawEmail === 'string' ? rawEmail.trim().toLowerCase() : '';
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'A valid email is required.' });
  }
  if (typeof displayName !== 'string' || !displayName.trim()) {
    return res.status(400).json({ error: 'Display name is required.' });
  }
  if (typeof password !== 'string' || password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  }

  try {
    const salt = randomBytes(16).toString('hex');
    const passwordHash = await scrypt(password, salt, 64);
    const user = {
      id: 'profile',
      emailKey: email,
      userId: randomUUID(),
      email,
      displayName: displayName.trim(),
      passwordHash: `scrypt$${salt}$${passwordHash.toString('hex')}`,
      role,
      status: 'active',
      createdAt: new Date().toISOString(),
    };

    await usersContainer.items.create(user);
    return res.status(201).json(toPublicUser(user));
  } catch (error) {
    if (error.code === 409 || error.statusCode === 409) {
      return res.status(409).json({ error: 'An account with this email already exists.' });
    }
    console.error('Failed to register user:', error.message);
    return res.status(500).json({ error: 'Unable to register user.' });
  }
});

// List projects from Cosmos DB for the Spark portal.
app.get('/api/projects', authenticate, async (req, res) => {
  if (!projectsContainer || (req.auth.role === 'applicant' && !applicationsContainer)) {
    return res.status(503).json({ error: 'Cosmos DB is not configured.' });
  }

  try {
    const { resources } = await projectsContainer.items
      .query('SELECT * FROM c')
      .fetchAll();

    let appliedProjectIds;
    if (req.auth.role === 'applicant') {
      const { resources: applications } = await applicationsContainer.items.query({
        query: 'SELECT c.projectId FROM c WHERE c.userId = @userId',
        parameters: [{ name: '@userId', value: req.auth.userId }],
      }).fetchAll();
      appliedProjectIds = new Set(applications.map((application) => application.projectId));
    }

    const projects = resources.map((project) => ({
      ...toProjectResponse(project),
      ...(appliedProjectIds ? { hasApplied: appliedProjectIds.has(project.projectId) } : {}),
    }));
    return res.json(projects);
  } catch (error) {
    console.error('Failed to list projects:', error.message);
    return res.status(500).json({ error: 'Unable to list projects.' });
  }
});

// List projects posted by the authenticated manager (or superAdmin).
app.get('/api/projects/mine', authenticate, requireRoles('manager', 'superAdmin'), async (req, res) => {
  if (!projectsContainer) {
    return res.status(503).json({ error: 'Cosmos DB is not configured.' });
  }

  try {
    const { resources } = await projectsContainer.items.query({
      query: 'SELECT * FROM c WHERE c.manager.userId = @managerId',
      parameters: [{ name: '@managerId', value: req.auth.userId }],
    }).fetchAll();
    return res.json(resources.map(toProjectResponse));
  } catch (error) {
    console.error('Failed to list manager projects:', error.message);
    return res.status(500).json({ error: 'Unable to list your projects.' });
  }
});

// Submit an application. The applicant's ID is also the item ID, preventing duplicate applications per project.
app.post('/api/projects/:projectId/applications', authenticate, requireRoles('applicant'), async (req, res) => {
  if (!projectsContainer || !usersContainer || !applicationsContainer) {
    return res.status(503).json({ error: 'Cosmos DB is not configured.' });
  }

  const { projectId } = req.params;
  const message = req.body?.message ?? '';
  if (typeof message !== 'string' || message.length > 2000) {
    return res.status(400).json({ error: 'Application message must be a string of at most 2000 characters.' });
  }

  try {
    const [{ resource: project }, applicant] = await Promise.all([
      projectsContainer.item(projectId, projectId).read(),
      getAuthenticatedUser(req.auth),
    ]);

    if (!project) return res.status(404).json({ error: 'Project not found.' });
    if (project.status !== 'open') {
      return res.status(409).json({ error: 'This project is not accepting applications.' });
    }
    if (!applicant || applicant.status !== 'active' || applicant.role !== 'applicant') {
      return res.status(403).json({ error: 'Active applicant account required.' });
    }

    const application = {
      id: applicant.userId,
      projectId,
      userId: applicant.userId,
      applicant: {
        displayName: applicant.displayName,
        email: applicant.email,
      },
      message: message.trim(),
      status: 'submitted',
      appliedAt: new Date().toISOString(),
    };

    await applicationsContainer.items.create(application);
    return res.status(201).json(toApplicationResponse(application));
  } catch (error) {
    if (error.code === 404 || error.statusCode === 404) {
      return res.status(404).json({ error: 'Project not found.' });
    }
    if (error.code === 409 || error.statusCode === 409) {
      return res.status(409).json({ error: 'You have already applied to this project.' });
    }
    console.error('Failed to submit project application:', error.message);
    return res.status(500).json({ error: 'Unable to submit application.' });
  }
});

// Applicants can list their own applications; this query spans project partitions.
app.get('/api/applications/me', authenticate, requireRoles('applicant'), async (req, res) => {
  if (!applicationsContainer) {
    return res.status(503).json({ error: 'Cosmos DB is not configured.' });
  }

  try {
    const { resources } = await applicationsContainer.items.query({
      query: 'SELECT * FROM c WHERE c.userId = @userId',
      parameters: [{ name: '@userId', value: req.auth.userId }],
    }).fetchAll();
    return res.json(resources.map(toApplicationResponse));
  } catch (error) {
    console.error('Failed to list user applications:', error.message);
    return res.status(500).json({ error: 'Unable to list applications.' });
  }
});

// A manager can view applicants only for projects they own; superAdmins can view any project's applicants.
app.get('/api/projects/:projectId/applications', authenticate, requireRoles('manager', 'superAdmin'), async (req, res) => {
  if (!projectsContainer || !applicationsContainer) {
    return res.status(503).json({ error: 'Cosmos DB is not configured.' });
  }

  const { projectId } = req.params;
  try {
    const { resource: project } = await projectsContainer.item(projectId, projectId).read();
    if (!project) return res.status(404).json({ error: 'Project not found.' });
    if (req.auth.role !== 'superAdmin' && project.manager?.userId !== req.auth.userId) {
      return res.status(403).json({ error: 'You can only view applicants for your own projects.' });
    }

    const { resources } = await applicationsContainer.items.query({
      query: 'SELECT * FROM c WHERE c.projectId = @projectId',
      parameters: [{ name: '@projectId', value: projectId }],
    }, { partitionKey: projectId }).fetchAll();
    return res.json(resources.map(toApplicationResponse));
  } catch (error) {
    if (error.code === 404 || error.statusCode === 404) {
      return res.status(404).json({ error: 'Project not found.' });
    }
    console.error('Failed to list project applicants:', error.message);
    return res.status(500).json({ error: 'Unable to list project applicants.' });
  }
});

// The manager who owns a project can decide an applicant's application.
app.patch('/api/projects/:projectId/applications/:userId', authenticate, requireRoles('manager'), async (req, res) => {
  if (!projectsContainer || !applicationsContainer) {
    return res.status(503).json({ error: 'Cosmos DB is not configured.' });
  }

  const { projectId, userId } = req.params;
  const { status } = req.body ?? {};
  if (!['selected', 'rejected'].includes(status)) {
    return res.status(400).json({ error: 'Status must be either selected or rejected.' });
  }

  try {
    const { resource: project } = await projectsContainer.item(projectId, projectId).read();
    if (!project) return res.status(404).json({ error: 'Project not found.' });
    if (project.manager?.userId !== req.auth.userId) {
      return res.status(403).json({ error: 'You can only update applications for your own projects.' });
    }

    const applicationItem = applicationsContainer.item(userId, projectId);
    const { resource: application } = await applicationItem.read();
    if (!application) return res.status(404).json({ error: 'Application not found for this project.' });

    const statusUpdatedAt = new Date().toISOString();
    const { resource: updatedApplication } = await applicationItem.patch([
      { op: 'set', path: '/status', value: status },
      { op: 'set', path: '/statusUpdatedAt', value: statusUpdatedAt },
      { op: 'set', path: '/statusUpdatedBy', value: req.auth.userId },
    ]);
    return res.json(toApplicationResponse(updatedApplication));
  } catch (error) {
    if (error.code === 404 || error.statusCode === 404) {
      return res.status(404).json({ error: 'Project or application not found.' });
    }
    console.error('Failed to update application status:', error.message);
    return res.status(500).json({ error: 'Unable to update application status.' });
  }
});

// Add a project to Cosmos DB.
app.post('/api/projects', authenticate, requireRoles('manager', 'superAdmin'), async (req, res) => {
  if (!projectsContainer) {
    return res.status(503).json({ error: 'Cosmos DB is not configured.' });
  }

  const { title, projectName, duration, description, status = 'open' } = req.body ?? {};
  if (typeof title !== 'string' || !title.trim()) {
    return res.status(400).json({ error: 'Project title is required.' });
  }
  if (typeof projectName !== 'string' || !projectName.trim()) {
    return res.status(400).json({ error: 'Project name is required.' });
  }
  if (typeof duration !== 'string' || !duration.trim()) {
    return res.status(400).json({ error: 'Project duration is required (for example, "8 weeks").' });
  }
  if (typeof description !== 'string' || !description.trim()) {
    return res.status(400).json({ error: 'Project description is required.' });
  }
  if (typeof status !== 'string' || !['open', 'closed'].includes(status)) {
    return res.status(400).json({ error: 'Status must be either open or closed.' });
  }

  try {
    const managerUser = await getAuthenticatedUser(req.auth);
    if (!managerUser || managerUser.status !== 'active' || managerUser.role !== req.auth.role) {
      return res.status(403).json({ error: 'Active manager account required.' });
    }

    const projectId = randomUUID();
    const project = {
      id: projectId,
      projectId,
      title: title.trim(),
      projectName: projectName.trim(),
      duration: duration.trim(),
      description: description.trim(),
      status,
      manager: {
        userId: managerUser.userId,
        displayName: managerUser.displayName,
        email: managerUser.email,
      },
      createdAt: new Date().toISOString(),
    };

    await projectsContainer.items.create(project);
    return res.status(201).json(project);
  } catch (error) {
    console.error('Failed to create project:', error.message);
    return res.status(500).json({ error: 'Unable to create project.' });
  }
});

// Connect and ensure the database containers exist before serving requests.
async function start() {
  if (hasCosmosCredentials()) {
    assertAuthConfig();
    const { containers } = await initializeCosmos();
    projectsContainer = containers.projects;
    usersContainer = containers.users;
    sessionsContainer = containers.sessions;
    applicationsContainer = containers.applications;
    console.log('Connected to Azure Cosmos DB and verified database containers.');
  } else {
    console.warn('Cosmos DB is not configured; database-backed API endpoints are unavailable.');
  }

  app.listen(PORT, () => {
    console.log(`Server is listening on http://localhost:${PORT}`);
  });
}

start().catch((error) => {
  console.error('Unable to start the server:', error.message);
  process.exitCode = 1;
});
