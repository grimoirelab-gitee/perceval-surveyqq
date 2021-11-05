#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Huawei
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
# Authors:
#     Yehui Wang <yehui.wang.mdh@gmail.com>

import json
import logging

import requests
from grimoirelab_toolkit.datetime import (datetime_to_utc,
                                          str_to_datetime, datetime_utcnow)
from grimoirelab_toolkit.uris import urijoin

from perceval.backend import (Backend,
                              BackendCommand,
                              BackendCommandArgumentParser,
                              DEFAULT_SEARCH_FIELD)
from perceval.client import HttpClient, RateLimitHandler
from perceval.utils import DEFAULT_DATETIME, DEFAULT_LAST_DATETIME
from sqlalchemy.sql.expression import true

DEFAULT_OFFSET = 0

CATEGORY_ISSUE = "issue"
CATEGORY_PULL_REQUEST = "pull_request"


SURVEYQQ_URL = "https://open.wj.qq.com/api/surveys"
GITEE_API_URL = "https://gitee.com/api/v5/repos"


# Range before sleeping until rate limit reset
MIN_RATE_LIMIT = 10
MAX_RATE_LIMIT = 500

# Use this factor of the current token's remaining API points before switching to the next token
TOKEN_USAGE_BEFORE_SWITCH = 0.1

MAX_CATEGORY_ITEMS_PER_PAGE = 100
PER_PAGE = 100

# Default sleep time and retries to deal with connection/server problems
DEFAULT_SLEEP_TIME = 1
MAX_RETRIES = 5

logger = logging.getLogger(__name__)


class Surveyqq(Backend):
    """Surveyqq backend for Perceval.

    This class allows the fetch the issues stored in Gitee repostory.
    ```
    Gitee(
        owner='chaoss', repository='grimoirelab',
        api_token=[TOKEN-1, TOKEN-2, ...], sleep_for_rate=True,
        sleep_time=300
    )
    ```
    """

    version = '0.1.0'

    CATEGORIES = [CATEGORY_ISSUE, CATEGORY_PULL_REQUEST]

    CLASSIFIED_FIELDS = [
        ['user_data'],
        ['merged_by_data'],
        ['assignee_data'],
        ['assignees_data'],
        ['requested_reviewers_data'],
        ['comments_data', 'user_data'],
        ['reviews_data', 'user_data'],
        ['review_comments_data', 'user_data']
    ]

    def __init__(self, owner=None, repository=None,
                 surveyid=None, appid=None,
                 api_token=None, max_retries=MAX_RETRIES, 
                 max_items=MAX_CATEGORY_ITEMS_PER_PAGE,
                 tag=None, archive=None, ssl_verify=True):
        origin = urijoin(SURVEYQQ_URL, surveyid, "answers")
        super().__init__(origin, tag=tag, archive=archive, ssl_verify=ssl_verify)

        self.owner = owner
        self.repository = repository
        self.surveyid = surveyid
        self.appid = appid
        self.api_token = api_token
        self.base_url = origin
        self.max_retries = max_retries
        self.max_items = max_items
        

    def fetch(self, category=CATEGORY_ISSUE, offset=DEFAULT_OFFSET):
        """Fetch the issues/pull requests from the repository.

        The method retrieves, from a GitHub repository, the issues/pull requests
        updated since the given date.

        :param category: the category of items to fetch
        :param from_date: obtain issues/pull requests updated since this date
        :param to_date: obtain issues/pull requests until a specific date (included)
        :param filter_classified: remove classified fields from the resulting items

        :returns: a generator of issues
        """
        if not offset:
            offset = DEFAULT_OFFSET

        kwargs = {
            "offset": offset
        }
        items = super().fetch(category, **kwargs)

        return items

    def fetch_items(self, category, **kwargs):
        """Fetch the items (issues or pull_requests or repo information)

        :param category: the category of items to fetch
        :param kwargs: backend arguments

        :returns: a generator of items
        """
        offset = kwargs['offset']

        if category == CATEGORY_ISSUE:
            items = self.__fetch_issues_survey(offset)
        else:
            items = self.__fetch_issues_survey(offset)

        return items

    @classmethod
    def has_archiving(cls):
        """Returns whether it supports archiving items on the fetch process.

        :returns: this backend supports items archive
        """
        return True

    @classmethod
    def has_resuming(cls):
        """Returns whether it supports to resume the fetch process.

        :returns: this backend supports items resuming
        """
        return True

    @staticmethod
    def metadata_id(item):
        """Extracts the identifier from a Gitee item."""

        return str(item['answer_id'])

    @staticmethod
    def metadata_updated_on(item):
        """Extracts the update time from a Gitee item.

        The timestamp used is extracted from 'updated_at' field.
        This date is converted to UNIX timestamp format. As Gitee
        dates are in UTC the conversion is straightforward.

        :param item: item generated by the backend

        :returns: a UNIX timestamp
        """
        ts = item['ended_at']
        ts = str_to_datetime(ts)

        return ts.timestamp()

    @staticmethod
    def metadata_category(item):
        """Extracts the category from a Gitee item.

        This backend generates three types of item which are
        'issue', 'pull_request' and 'repo' information.
        """

        return CATEGORY_ISSUE

    def _init_client(self, from_archive=False):
        """Init client"""

        return SurveyqqClient(self.owner, self.repository, self.base_url,
                           self.appid, self.api_token,self.max_retries, self.max_items,
                           self.archive, from_archive, self.ssl_verify)

    def __fetch_issues_survey(self, offset):
        """Fetch the issues"""
        #fetch survey from each page.
        issues__survey_groups = self.client.fetch_items(offset=offset)

        for issue_surveys in issues__survey_groups:
            for issue_survey in issue_surveys:
                issue_survey["issue_data"] = self._get_issue(issue_survey["answer"][0]["questions"][1]["text"])
                issue_survey["comment_data"] = self.__get_issue_comments(issue_survey["answer"][0]["questions"][1]["text"])
                yield issue_survey

    def _get_issue(self, issue_link):
        issue_link_split = issue_link.split('/')
        if issue_link_split[-4] == self.owner and issue_link_split[-3] == self.repository:
            issue_surfix = '/'.join(issue_link_split[-4:])
            issue_raw = self.client.issue(issue_surfix)
            return json.loads(issue_raw)
        else:
            return "Invalid Issue Link"
    
    def __get_issue_comments(self, issue_link):
        """Get issue comments"""
        issue_link_split = issue_link.split('/')
        if issue_link_split[-4] == self.owner and issue_link_split[-3] == self.repository:
            issue_surfix = '/'.join(issue_link_split[-4:])
            issue_comment_raw = self.client.issue_comment(issue_surfix)
            return json.loads(issue_comment_raw)
        else:
            return "Invalid Issue Link"
        # comments = []
        # group_comments = self.client.issue_comments(issue_number)

        # for raw_comments in group_comments:

        #     for comment in json.loads(raw_comments):
        #         comment_id = comment.get('id')
        #         comment['user_data'] = self.__get_user(comment['user']['login'])
        #         comments.append(comment)

        # return comments

class SurveyqqClient(HttpClient, RateLimitHandler):
    """Client for retrieving information from Gitee API

    :param owner: Gitee owner
    :param repository: Gitee repository from the owner
    :param tokens: list of Gitee auth tokens to access the API
    :param base_url: Gitee URL in enterprise edition case;
        when no value is set the backend will be fetch the data
        from the Gitee public site.
    :param sleep_for_rate: sleep until rate limit is reset
    :param min_rate_to_sleep: minimun rate needed to sleep until
         it will be reset
    :param sleep_time: time to sleep in case
        of connection problems
    :param max_retries: number of max retries to a data source
        before raising a RetryError exception
    :param max_items: max number of category items (e.g., issues,
        pull requests) per query
    :param archive: collect issues already retrieved from an archive
    :param from_archive: it tells whether to write/read the archive
    :param ssl_verify: enable/disable SSL verification
    """
    EXTRA_STATUS_FORCELIST = [403, 500, 502, 503]

    _users = {}  # users cache
    _users_orgs = {}  # users orgs cache

    def __init__(self, owner, repository, base_url=None, appid=None,
                 api_token=None,  max_retries=MAX_RETRIES,
                 max_items=MAX_CATEGORY_ITEMS_PER_PAGE, archive=None, from_archive=False, ssl_verify=True):
        self.max_items = max_items
        self.owner = owner
        self.repository = repository
        self.base_url = base_url
        self.appid = appid
        self.api_token = api_token

        super().__init__(base_url, max_retries=max_retries,
                         extra_headers=self._set_extra_headers(),
                         extra_status_forcelist=self.EXTRA_STATUS_FORCELIST,
                         archive=archive, from_archive=from_archive, ssl_verify=ssl_verify)
        # refresh the access token
        # self._refresh_access_token()



    def issue(self, issue_surfix=None):
        """Fetch the issues from the repository.

        The method retrieves, from a Gitee repository, the issues
        updated since the given date.

        :param from_date: obtain issues updated since this date


        :returns: a generator of issues
        """
        path = urijoin(GITEE_API_URL, issue_surfix)
        r = self.fetch(path)
        return r.text
    
    def issue_comment(self, issue_surfix=None):
        path = urijoin(GITEE_API_URL, issue_surfix, "comments")
        payload = {
            'page':100,
            'per_page': PER_PAGE,
            'order': 'asc',
        }
        r = self.fetch(path,payload)
        return r.text



    def fetch(self, url, payload=None, headers=None, method=HttpClient.GET, stream=False, auth=None):
        """Fetch the data from a given URL.

        :param url: link to the resource
        :param payload: payload of the request
        :param headers: headers of the request
        :param method: type of request call (GET or POST)
        :param stream: defer downloading the response body until the response content is available
        :param auth: auth of the request

        :returns a response object
        """
        response = super().fetch(url, payload, headers, method, stream, auth)

        # if not self.from_archive:
        #    if self._need_check_tokens():
        #        self._choose_best_api_token()
        #    else:
        #        self.update_rate_limit(response)

        return response

    def fetch_items(self, offset=None):
        """Return the items from gitee API using links pagination"""

        payload = {
            'appid': self.appid,
            'access_token': self.api_token,
            'last_answer_id': offset,
            'per_page': self.max_items
        }

        page = 0  # current page
        logger.debug("Get Gitee paginated items from " + self.base_url)

        response = self.fetch(self.base_url, payload=payload)

        items = json.loads(response.text)["data"]

        while items["list"]:
            page += 1
            logger.debug("Page: %i" % (page))
            yield items["list"]
            last_answer_id = items["last_answer_id"]           
            items = None
            payload['last_answer_id'] = last_answer_id
            response = self.fetch(self.base_url, payload=payload)
            items = json.loads(response.text)["data"]

    def _set_extra_headers(self):
        """Set extra headers for session"""
        headers = {}
        # set the header for request
        headers.update({'Content-Type': 'application/json;charset=UTF-8'})
        return headers

    # def _refresh_access_token(self):
    #     """Send a refresh post access to the Gitee Server"""
    #     if self.access_token:
    #         url = GITEE_REFRESH_TOKEN_URL + "?grant_type=refresh_token&refresh_token=" + self.access_token
    #         logger.info("Refresh the access_token for Gitee API")
    #         self.session.post(url, data=None, headers=None, stream=False, auth=None)


class SurveyqqCommand(BackendCommand):
    """Class to run Gitee backend from the command line."""

    BACKEND = Surveyqq

    @classmethod
    def setup_cmd_parser(cls):
        """Returns the Gitee argument parser."""

        parser = BackendCommandArgumentParser(cls.BACKEND,
                                              offset=True,
                                              token_auth=True,
                                              archive=True,
                                              ssl_verify=True)

        action = parser.parser._option_string_actions['--api-token']
        action.required = True

        # Gitee options
        group = parser.parser.add_argument_group('Surveyqq arguments')
        group.add_argument('--surveyid', dest='surveyid',
                           help="surveyid")

        group.add_argument('--appid', dest='appid',
                           help="appid")

        # Generic client options
        group.add_argument('--max-items', dest='max_items',
                           default=MAX_CATEGORY_ITEMS_PER_PAGE, type=int,
                           help="Max number of category items per query.")
        group.add_argument('--max-retries', dest='max_retries',
                           default=MAX_RETRIES, type=int,
                           help="number of API call retries")

        # Positional arguments
        parser.parser.add_argument('owner',
                                   help="Gitee owner")
        parser.parser.add_argument('repository',
                                   help="Gitee repository")
        return parser

if __name__ == "__main__":
    survey = Surveyqq(owner="xxx", repository="xxx", surveyid=xxx, appid="xx",
                 api_token="xxx",
                 max_items=4,
                 tag=None, archive=None, ssl_verify=True)
    answers = [answer for answer in survey.fetch(offset=0)]
    issue1 = answers[0]
    with open('data.json', 'w', encoding='utf-8') as f:
        json.dump(issue1, f, ensure_ascii=False, indent=4)

