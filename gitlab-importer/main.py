#!/usr/bin/env python
#

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
from future import standard_library

import logging
import os
import requests
import sys
import time
import uuid
import yaml
from lxml.html import fromstring
from subprocess import Popen, PIPE


standard_library.install_aliases()

# Enable verified HTTPS requests on older Pythons
# http://urllib3.readthedocs.org/en/latest/security.html
if sys.version_info[0] == 2:
    requests.packages.urllib3.contrib.pyopenssl.inject_into_urllib3()
    from urllib import quote
    from urllib import urlencode
else:
    from urllib.parse import quote
    from urllib.parse import urlencode

logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.DEBUG)

try:
    config = yaml.load(open('conf/setting.yml').read())
    SOURCE_HOST = config['source_host']
    SOURCE_HOST_TOKEN = config['source_host_token']
    DEST_HOST = config['dest_host']
    DEST_HOST_TOKEN = config['dest_host_token']
    NEW_USER_PASSWORD = config['new_user_password']
    SEND_EMAIL = config['send_email']
    REQUESET_TIMEOUT = config['requeset_timeout']
    GIT_BINARY_PATH = config['git_binary_path']

except KeyError:
    logger.error("Unable to load config file.")
    sys.exit(1)


def _makeGetRequest(target, url, params={}):
    data_list = []
    parameters = {
        'page': 1,
        'per_page': 20
    }

    for key in params.keys():
        parameters[key] = params[key]

    if target == 'src':
        url = "%sapi/v3/%s" % (SOURCE_HOST, url)
        headers = {'PRIVATE-TOKEN': SOURCE_HOST_TOKEN}
    else:
        url = "%sapi/v3/%s" % (DEST_HOST, url)
        headers = {'PRIVATE-TOKEN': DEST_HOST_TOKEN}

    req_url = "%s?%s" % (url, urlencode(parameters))

    while True:
        req = requests.get(req_url, headers=headers, timeout=REQUESET_TIMEOUT)

        req.raise_for_status()

        # Copy data
        data = req.json()
        if type(data) is dict:
            data_list.append(data)
        else:
            data_list.extend(data)

        # Parse header link
        if not req.headers.get('Link'):
            break

        link = requests.utils.parse_header_links(req.headers['Link'])
        next_link = None

        for l in link:
            if l.get('rel') == 'next':
                next_link = l['url']
                req_url = l['url']

        if not next_link:
            break

        time.sleep(1)

    return data_list


def _makePostRequest(target, url, form_data=None):

    if target == 'src':
        url = "%sapi/v3/%s" % (SOURCE_HOST, url)
        headers = {'PRIVATE-TOKEN': SOURCE_HOST_TOKEN}
    else:
        url = "%sapi/v3/%s" % (DEST_HOST, url)
        headers = {'PRIVATE-TOKEN': DEST_HOST_TOKEN}

    req = requests.post(url, data=form_data,
                        headers=headers, timeout=REQUESET_TIMEOUT)

    return req


def _resetPassword(user):
    s = requests.Session()
    html = s.get("%susers/sign_in" % DEST_HOST)
    tree = fromstring(html.text)
    token = tree.xpath('//meta[@name="csrf-token"]/@content')

    if len(token):
        data = {'authenticity_token': token[0],
                'user[email]': user['email']
                }
        s.post("%susers/password" % DEST_HOST, data=data)
    else:
        raise RuntimeWarning("Cant get reset password page token.")


def perCheck():
    logger.info("PerChecking...")

    new_user = []
    new_group = []
    group_link = {}
    new_project = []

    # Check user
    old_user = _makeGetRequest('src', "users")
    current_user = _makeGetRequest('dest', "users")
    for r in old_user:
        name = r['name']
        username = r['username']
        email = r['email']
        # is_admin = r['is_admin']

        if r['state'] == 'blocked':
            continue

        not_user = True
        for cu in current_user:
            if cu['username'] == username:
                logger.warning("User: %s already existed.", username)
                not_user = False
                break

        if not_user:
            new_user.append({
                            'name': name,
                            'username': username,
                            'email': email,
                            # 'is_admin': is_admin
                            })

    # Check project
    old_project = _makeGetRequest('src', "projects/all")
    current_project = _makeGetRequest('dest', "projects/all")
    for r in old_project:
        project_name = r['name']
        group_name = r['namespace']['name']
        path_with_namespace = r['path_with_namespace']

        not_project = True
        for cp in current_project:
            if cp['path_with_namespace'] == path_with_namespace:
                logger.warning("Project: %s already existed.", project_name)
                not_project = False
                break

        if not_project:
            new_project.append({
                               'name': project_name,
                               'path': r['path'],
                               'group': r['namespace']['name'],
                               'description': r['description'],
                               'public': r['public'],
                               'visibility_level': r['visibility_level'],
                               'old_link': r['ssh_url_to_repo']
                               })

    # Check group
    old_group = _makeGetRequest('src', "namespaces")
    current_group = _makeGetRequest('dest', "namespaces")
    for r in old_group:
        group_name = r['path']
        not_group = True

        for cg in current_group:
            if group_name == cg['path']:
                logger.warning("Group: %s already existed.", group_name)
                not_group = False

                group_link[group_name] = cg['id']
                break

        if not_group and r['kind'] == 'group':
            # FIXME: if group name not equal group path
            # this will overwirt group name
            new_group.append({'name': r['path'], 'path': r['path']})

    return {'user': new_user, 'group': new_group,
            'project': new_project, 'group_link': group_link
            }


# Create group, user and project
def perTrans(data):
    user = data.get('user')
    group = data.get('group')
    project = data.get('project')
    group_link = data.get('group_link')

    user_cd = ''
    user_fd = ''
    group_cd = ''
    group_fd = ''
    project_cd = ''
    project_fd = ''

    if user:
        logger.info("Create users...")
        for u in user:
            u['password'] = NEW_USER_PASSWORD
            ru = _makePostRequest('dest', "users",
                                  form_data=u,
                                  )
            if ru.status_code == 201:
                user_cd = "%s %s" % (user_cd, u['name'])

                if SEND_EMAIL:
                    _resetPassword(u)
            else:
                user_fd = "%s %s" % (user_fd, u['name'])

        if user_cd:
            logger.info("Create users: (%s) success.", user_cd)

        if user_fd:
            logger.info("Create users: (%s) failed.", user_fd)

    if group:
        logger.info("Create groups...")
        for g in group:
            rg = _makePostRequest('dest', "groups",
                                  form_data=g,
                                  )
            if rg.status_code == 201:
                group_cd = "%s %s" % (group_cd, g['path'])
                r = rg.json()
                group_link[r['path']] = r['id']
            else:
                group_fd = "%s %s" % (group_fd, g['path'])

        if group_cd:
            logger.info("Create groups: (%s) success.", group_cd)

        if group_fd:
            logger.info("Create groups: (%s) failed.", group_fd)

    if project:
        logger.info("Create projects...")
        for idx, p in enumerate(project):
            project_data = p.copy()
            project_data.pop('old_link', None)
            project_data.pop('group')
            project_data['namespace_id'] = group_link.get(p['group'])

            rp = _makePostRequest('dest', "projects",
                                  form_data=project_data,
                                  )

            if rp.status_code == 201:
                project_cd = "%s %s" % (project_cd, p['name'])
                r = rp.json()
                p['new_link'] = r['ssh_url_to_repo']
                project[idx] = p
            else:
                project_fd = "%s %s" % (project_fd, p['name'])

        if project_cd:
            logger.info("Create projects: (%s) success.", project_cd)

        if project_fd:
            logger.info("Create projects: (%s) failed.", project_fd)

        data['project'] = project
        return data


def startTrans(data):
    run_dir = os.path.dirname(os.path.realpath(__file__))
    tmp_dir = "%s/i_%s" % (run_dir, uuid.uuid4().hex.upper()[0:6])
    os.makedirs(tmp_dir)
    project = data['project']
    group = data['group']

    for g in group:
        dir = "%s/%s" % (tmp_dir, g['path'])
        if not os.path.exists(dir):
            os.makedirs(dir)

    logger.info("Donwloading project... ")

    for p in project:

        dir = "%s/%s" % (tmp_dir, p['group'])
        if not os.path.exists(dir):
            os.makedirs(dir)

        os.chdir(dir)

        po = Popen('%s clone %s' % (GIT_BINARY_PATH, p['old_link']),
                   shell=True, stdin=PIPE,
                   stdout=PIPE, close_fds=True, bufsize=1,
                   universal_newlines=True)
        output, err = po.communicate()
        if po.returncode != 0:
            logger.error("Can't clone project %s. %s", p['name'], err)
            continue

        os.chdir("%s/%s" % (dir, p['path']))

        po = Popen('%s remote set-url origin %s' % (GIT_BINARY_PATH, p['new_link']),
                   shell=True, stdin=PIPE,
                   stdout=PIPE, close_fds=True, bufsize=1,
                   universal_newlines=True)
        output, err = po.communicate()
        if po.returncode != 0:
            logger.error("Can't add git remote link %s. %s", p['name'], err)
            continue

        po = Popen("%s push '*:*'" % GIT_BINARY_PATH,
                   shell=True, stdin=PIPE,
                   stdout=PIPE, close_fds=True, bufsize=1,
                   universal_newlines=True)
        output, err = po.communicate()

        po = Popen("%s push --all" % GIT_BINARY_PATH,
           shell=True, stdin=PIPE,
           stdout=PIPE, close_fds=True, bufsize=1,
           universal_newlines=True)
        output, err = po.communicate()
        if po.returncode != 0:
            logger.error("Can't push to remote repo %s. %s", p['name'], err)

    os.chdir(run_dir)
    #os.removedirs(tmp_dir)
    return


def main():
    data = {}
    logger.info("String transmission...")
    data = perCheck()
    data = perTrans(data)
    startTrans(data)


if __name__ == '__main__':
    main()
