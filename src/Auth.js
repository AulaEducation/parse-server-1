const cryptoUtils = require('./cryptoUtils');
const RestQuery = require('./RestQuery');
const Parse = require('parse/node');

// An Auth object tells you who is requesting something and whether
// the master key was used.
// userObject is a Parse.User and can be null if there's no user.
function Auth({ config, isMaster = false, isReadOnly = false, user, installationId } = {}) {
  this.config = config;
  this.installationId = installationId;
  this.isMaster = isMaster;
  this.user = user;
  this.isReadOnly = isReadOnly;

  // Assuming a users roles won't change during a single request, we'll
  // only load them once.
  this.userRoles = [];
  this.fetchedRoles = false;
  this.rolePromise = null;
}

// Whether this auth could possibly modify the given user id.
// It still could be forbidden via ACLs even if this returns true.
Auth.prototype.couldUpdateUserId = function(userId) {
  if (this.isMaster) {
    return true;
  }
  if (this.user && this.user.id === userId) {
    return true;
  }
  return false;
};

// A helper to get a master-level Auth object
function master(config) {
  return new Auth({ config, isMaster: true });
}

// A helper to get a master-level Auth object
function readOnly(config) {
  return new Auth({ config, isMaster: true, isReadOnly: true });
}

// A helper to get a nobody-level Auth object
function nobody(config) {
  return new Auth({ config, isMaster: false });
}


// Returns a promise that resolves to an Auth object
var getAuthForSessionToken = function({ config, sessionToken, installationId } = {}) {
  return config.cacheController.user.get(sessionToken).then((userJSON) => {
    if (userJSON) {
      const cachedUser = Parse.Object.fromJSON(userJSON);
      return Promise.resolve(new Auth({config, isMaster: false, installationId, user: cachedUser}));
    }

    var restOptions = {
      limit: 1,
      include: 'user'
    };

    var query = new RestQuery(config, master(config), '_Session', {sessionToken}, restOptions);
    return query.execute().then((response) => {
      var results = response.results;
      if (results.length !== 1 || !results[0]['user']) {
        throw new Parse.Error(Parse.Error.INVALID_SESSION_TOKEN, 'invalid session token');
      }

      var now = new Date(),
        expiresAt = results[0].expiresAt ? new Date(results[0].expiresAt.iso) : undefined;
      if (expiresAt < now) {
        throw new Parse.Error(Parse.Error.INVALID_SESSION_TOKEN,
          'Session token is expired.');
      }
      var obj = results[0]['user'];
      delete obj.password;
      obj['className'] = '_User';
      obj['sessionToken'] = sessionToken;
      config.cacheController.user.put(sessionToken, obj);
      const userObject = Parse.Object.fromJSON(obj);
      return new Auth({config, isMaster: false, installationId, user: userObject});
    });
  });
};

var getAuthForLegacySessionToken = function({config, sessionToken, installationId } = {}) {
  var restOptions = {
    limit: 1
  };
  var query = new RestQuery(config, master(config), '_User', { sessionToken: sessionToken}, restOptions);
  return query.execute().then((response) => {
    var results = response.results;
    if (results.length !== 1) {
      throw new Parse.Error(Parse.Error.INVALID_SESSION_TOKEN, 'invalid legacy session token');
    }
    const obj = results[0];
    obj.className = '_User';
    const userObject = Parse.Object.fromJSON(obj);
    return new Auth({config, isMaster: false, installationId, user: userObject});
  });
}

/**
 * Start custom role assignment
 */

function extractFirstWord(str) {
  return str.split('-')[0];
}

function hasStringInArray(str, array) {
  return array.indexOf(str) > -1;
}

function getClassRoles(allCustomRoles, className) {
  return allCustomRoles.filter(ac => hasStringInArray(className, ac.permissions.map(p => extractFirstWord(p))));
}

function flattenArray(array) {
  return array.reduce((a, b) => b ? a.concat(b) : a, []);
}

function removeEmptyValue(array) {
  return array.filter(a => !!a);
}

function filterDuplication(array) {
  return array.filter((v, i, a) => i == a.indexOf(v));
}

function getUserRoles(allCustomRoles, uRoles, userId) {
  if (!uRoles || !uRoles.length) {
    return [];
  }

  const rawRoles = allCustomRoles
    .filter(ac => hasStringInArray(ac.role, uRoles))
    .map(uR => uR.permissions);

  const roles = flattenArray(rawRoles);
  const userRoles = roles.concat(userId);

  return userRoles;
}

function transformUserRoles(roles) {
  const roleMap = {
    create: 'write',
    update: 'write',
    read: 'read'
  };

  const tRoles = roles.map(r => {
    const [cName, cRole] = r.split('-');

    if (roleMap[cRole]) {
      return `role:${cName}-${roleMap[cRole]}`;
    }

    return `role:${cName}`;
  });

  return filterDuplication(tRoles);
}

function transfromClassRoles(matchedRole, className, spaceId) {
  const roleMap = {
    create: 'write',
    update: 'write',
    read: 'read'
  };

  if (!matchedRole) {
    return [];
  }

  return matchedRole.permissions.map(p => {
    const [cName, permisson] = p.split('-');

    if (cName === className) {
      return {
        role: `role:${cName}-${spaceId}-${roleMap[permisson]}`,
        isCreate: permisson === 'create'
      };
    }

    // support legacy role system
    if (cName === 'classRoom') {
      return {
        role: `role:${cName}-${spaceId}-${permisson}`,
      }
    }
  });
}

function isNewRoleEnabled(allRoles) {
  const rootRole = allRoles.find(ar => ar.role === 'root');

  return rootRole && rootRole.permissions && rootRole.permissions[0] === 'all';
}


// for direct roles such as direct message
Auth.prototype._getAllCustomRoles = function () {
  return this._queryByClassName({}, 'UBRoleDefinition');
};

Auth.prototype._queryToSpace = function (restWhere, className) {
  return this._queryByClassName(restWhere, className)
    .then(objs => {
      if (objs.length > 0) {
        const obj = objs[0];

        if (obj.classRoom) {
          return obj.classRoom;
        }

        if (obj.post && obj.objectId) {
          const restWhereNext = { objectId: obj.post.objectId };
          const classNameNext = obj.post.className;

          return this._queryToSpace(restWhereNext, classNameNext);
        }

        return null;
      }

      return null;
    });
};

Auth.prototype.getSpacePointer = function (className, data, query, restQuery) {
  if (data && data.classRoom) {
    return Promise.resolve(data.classRoom);
  }

  if (restQuery && restQuery.classRoom) {
    return Promise.resolve(restQuery.classRoom);
  }

  let restWhere, restClass;

  if (data && data.post && data.post.objectId) {
    restWhere = { objectId: data.post.objectId };
    restClass = data.post.className;
  }

  if (data && data.itemType && data.itemId) {
    restWhere = { objectId: data.itemId };
    restClass = data.itemType;
  }

  if (query && query.objectId) {
    restWhere = { objectId: query.objectId };
    restClass = className;
  }

  console.log(`
    restWhere: ${JSON.stringify(restWhere)}, restClass: ${restClass}
  `);

  return restWhere && restClass
    ? this._queryToSpace(restWhere, restClass)
    : Promise.resolve();
};

// Returns a promise that resolves to an array of role names
Auth.prototype.getUserRoles = function (className, data, query, restQuery) {
  console.log(`
    Incoming data:
    - className: ${className}
    - data: ${JSON.stringify(data)}
    - query: ${JSON.stringify(query)}
    - restQuery: ${JSON.stringify(restQuery)}
  `);

  if (this.isMaster || !this.user) {
    return Promise.resolve([]);
  }

  if (this.fetchedRoles) {
    return Promise.resolve(this.userRoles);
  }

  if (this.rolePromise) {
    return this.rolePromise;
  }

  // load general roles based on user.generalRole
  return this._getAllCustomRoles().then((acRoles) => {
    // check if we're using new role system
    // if use new role system, we should add root role with permissions = ['all'] to UBRoleDefinition
    if (!isNewRoleEnabled(acRoles)) {
      this.rolePromise = this._loadRoles([]);

      return this.rolePromise;
    } else {
      return this.getSpacePointer(className, data, query, restQuery).then((spacePointer) => {
        console.log(`
          space pointer: ${JSON.stringify(spacePointer)}
        `);

        const classRoles = getClassRoles(acRoles, className);
        const userRoles = getUserRoles(acRoles, this.user.get('userRoles'), this.user.id);
        const tUserRoles = transformUserRoles(userRoles);
        const isCreateRequest = (!data || !data.objectId) && (!query || !query.objectId);

        if (classRoles.length && spacePointer) {
          this.rolePromise = this._loadCustomRoles(tUserRoles, classRoles, className, spacePointer, isCreateRequest);
        } else {
          // check if user can create new object
          const roleName = `${className}-create`;
          const canCreate = userRoles.indexOf(roleName) > -1;

          if (isCreateRequest && !canCreate) {
            throw new Parse.Error(Parse.Error.OPERATION_FORBIDDEN, `User ${this.user.id} is not allowed to create new object in ${className}`);
          }

          this.rolePromise = this._loadRoles(tUserRoles);
        }

        return this.rolePromise;
      });
    }
  });
};

Auth.prototype._queryByClassName = function (restWhere, className) {
  return new Promise(resolve => {
    const query = new RestQuery(this.config, master(this.config), className, restWhere, {});

    return query.execute().then(response => resolve(response.results));
  });
};

Auth.prototype._loadCustomRoles = function (userRoles, classRoles, className, spacePointer, isCreateRequest) {
  const restWhere = {
    user: {
      __type: 'Pointer',
      className: '_User',
      objectId: this.user.id
    },
    classRoom: spacePointer
  };

  return this._queryByClassName(restWhere, 'UBClassRoomUser').then(results => {
    // Nothing found
    // user doesn't have any permission on this object
    if (!results.length) {
      throw new Parse.Error(Parse.Error.OPERATION_FORBIDDEN, `User ${this.user.id} is not allowed to access space ${spacePointer.objectId}`);
    }

    // a user may have multiple roles in one space: [{ role: 'student' }, { role: 'instructor' }]
    // from these roles, get permissions such as read, write
    const userClassRoles = results.map(result => {
      // current space id
      const spaceId = result.classRoom.objectId;

      // user role ('create', 'update', or 'read') in this `className` in this `space`
      // for example: user A in class B, the roles for object C (with spaceId = B) are ['create', 'update', 'read']
      const matchedRole = classRoles.find(cr => cr.role === result.role);

      return transfromClassRoles(matchedRole, className, spaceId);
    });

    // flatten roles to an array of objects
    const flattenUserClassRoles = removeEmptyValue(flattenArray(userClassRoles));

    // if this is new object, and user can't create, reject the request
    // isCreateRequest is passed from RestWrite,
    // indicate that this is write request, with no objectId
    const canCreate = flattenUserClassRoles.reduce((a, b) => a || b.isCreate, false);

    if (isCreateRequest && !canCreate) {
      throw new Parse.Error(Parse.Error.OPERATION_FORBIDDEN, `User ${this.user.id} is not allowed to create new object in ${className}`);
    }

    const cRoles = flattenUserClassRoles.map(uR => uR.role);
    const tCRoles = filterDuplication(cRoles);

    this.userRoles = tCRoles.concat(userRoles);
    this.fetchedRoles = true;
    this.rolePromise = null;

    console.log(`
      new user roles:
      ${this.userRoles}
    `);

    return Promise.resolve(this.userRoles);
  });
};

// Iterates through the role tree and compiles a users roles
Auth.prototype._loadRoles = function (uRoles) {
  var cacheAdapter = this.config.cacheController;
  return cacheAdapter.role.get(this.user.id).then(cachedRoles => {
    if (cachedRoles != null) {
      this.fetchedRoles = true;
      this.userRoles = cachedRoles;
      return Promise.resolve(cachedRoles);
    }

    var restWhere = {
      'users': {
        __type: 'Pointer',
        className: '_User',
        objectId: this.user.id
      }
    };
    // First get the role ids this user is directly a member of
    var query = new RestQuery(this.config, master(this.config), '_Role', restWhere, {});
    return query.execute().then(response => {
      var results = response.results;
      if (!results.length) {
        this.userRoles = [];
        this.fetchedRoles = true;
        this.rolePromise = null;

        cacheAdapter.role.put(this.user.id, Array(...this.userRoles));
        return Promise.resolve(this.userRoles);
      }
      var rolesMap = results.reduce((m, r) => {
        m.names.push(r.name);
        m.ids.push(r.objectId);
        return m;
      }, { ids: [], names: [] });

      // run the recursive finding
      return this._getAllRolesNamesForRoleIds(rolesMap.ids, rolesMap.names).then(roleNames => {
        const userRoles = roleNames.map(r => {
          return 'role:' + r;
        });

        this.userRoles = userRoles.concat(uRoles);
        this.fetchedRoles = true;
        this.rolePromise = null;
        cacheAdapter.role.put(this.user.id, Array(...this.userRoles));

        console.log(`
          legacy user roles:
          ${this.userRoles}
        `);

        return Promise.resolve(this.userRoles);
      });
    });
  });
};

// Given a list of roleIds, find all the parent roles, returns a promise with all names
Auth.prototype._getAllRolesNamesForRoleIds = function(roleIDs, names = [], queriedRoles = {}) {
  const ins = roleIDs.filter((roleID) => {
    return queriedRoles[roleID] !== true;
  }).map((roleID) => {
    // mark as queried
    queriedRoles[roleID] = true;
    return {
      __type: 'Pointer',
      className: '_Role',
      objectId: roleID
    }
  });

  // all roles are accounted for, return the names
  if (ins.length == 0) {
    return Promise.resolve([...new Set(names)]);
  }
  // Build an OR query across all parentRoles
  let restWhere;
  if (ins.length == 1) {
    restWhere = { 'roles': ins[0] };
  } else {
    restWhere = { 'roles': { '$in': ins }}
  }
  const query = new RestQuery(this.config, master(this.config), '_Role', restWhere, {});
  return query.execute().then((response) => {
    var results = response.results;
    // Nothing found
    if (!results.length) {
      return Promise.resolve(names);
    }
    // Map the results with all Ids and names
    const resultMap = results.reduce((memo, role) => {
      memo.names.push(role.name);
      memo.ids.push(role.objectId);
      return memo;
    }, {ids: [], names: []});
    // store the new found names
    names = names.concat(resultMap.names);
    // find the next ones, circular roles will be cut
    return this._getAllRolesNamesForRoleIds(resultMap.ids, names, queriedRoles)
  }).then((names) => {
    return Promise.resolve([...new Set(names)])
  })
}

const createSession = function(config, {
  userId,
  createdWith,
  installationId,
  additionalSessionData,
}) {
  const token = 'r:' + cryptoUtils.newToken();
  const expiresAt = config.generateSessionExpiresAt();
  const sessionData = {
    sessionToken: token,
    user: {
      __type: 'Pointer',
      className: '_User',
      objectId: userId
    },
    createdWith,
    restricted: false,
    expiresAt: Parse._encode(expiresAt)
  };

  if (installationId) {
    sessionData.installationId = installationId
  }

  Object.assign(sessionData, additionalSessionData);
  // We need to import RestWrite at this point for the cyclic dependency it has to it
  const RestWrite = require('./RestWrite');

  return {
    sessionData,
    createSession: () => new RestWrite(config, master(config), '_Session', null, sessionData).execute()
  }
}

module.exports = {
  Auth,
  master,
  nobody,
  readOnly,
  getAuthForSessionToken,
  getAuthForLegacySessionToken,
  createSession,
};
