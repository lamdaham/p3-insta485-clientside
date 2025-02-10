"""Verify that Project 3 Wrapper has been completed."""

from pathlib import Path
import bs4
import markdown


def test_valid_wrapper():
    """Check for and validate wrapper.md."""

    # make sure file exists
    assert Path("wrapper.md").exists()

    with open("wrapper.md", encoding="utf-8") as wrapper_file:
        wrapper_text = wrapper_file.read()

    # parse markdown
    html_text = markdown.markdown(wrapper_text, extensions=["attr_list"])
    soup = bs4.BeautifulSoup(html_text, "html.parser")

    # check valid format
    num_q = 3
    for i in range(1, num_q + 1):
        qid = f"Q{i}"
        question = soup.find(id=qid)
        assert question, f"Failed to find Question {qid}"

        answer = question.find_next()
        text = answer.text.strip()
        assert text, f"No answer to question {qid} found"
        assert text != "FIXME"
