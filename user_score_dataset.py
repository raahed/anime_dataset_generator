import csv
from tqdm import tqdm
from mal_auth import api_get


API = "https://api.myanimelist.net/v2"


def fetch_user_list(username: str):
    url = f"{API}/users/{username}/animelist"
    params = {"limit": 1000, "fields": "list_status"}  # id/title are returned by default
    items = []
    # per-user pagination progress
    pages = 0
    pager = tqdm(desc=f"Pages", unit="page", leave=False)
    try:
        while True:
            r = api_get(url, params=params)
            if r.status_code != 200:
                return []
            data = r.json()
            items.extend(data.get("data", []))
            pages += 1
            pager.update(1)
            pager.set_postfix_str(f"pages={pages} items={len(items)}")
            next_url = data.get("paging", {}).get("next")
            if not next_url:
                break
            url, params = next_url, None  # next already contains query params
    finally:
        pager.close()
    return items


def fetch_user_scores():
    with open("userlist/userlist.csv", "r", newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    with open("user_score.csv", "w", newline="", encoding="utf-8") as out:
        w = csv.writer(out)
        w.writerow(["user_id", "Username", "anime_id", "Anime Title", "rating"])

        iterator = tqdm(rows, desc="Users", unit="user")

        for row in iterator:
            username, user_id = row["username"], row["user_id"]
            iterator.set_postfix_str(f"fetching: {username}")
            items = fetch_user_list(username)
            data = []
            for it in items:
                node = it.get("node", {})
                ls = it.get("list_status", {})
                score = ls.get("score") or 0
                if score:
                    data.append([user_id, username, node.get("id"), node.get("title"), score])
            if data:
                w.writerows(data)

if __name__ == "__main__":
    fetch_user_scores()