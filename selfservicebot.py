import boto3
import selfservicebot as st
import os
from ghapi.all import GhApi
import time
import base64

st.subheader('RAG Using Knowledge Base from Amazon Bedrock', divider='rainbow')

if 'chat_history' not in st.session_state:
    st.session_state.chat_history = []

for message in st.session_state.chat_history:
    with st.chat_message(message['role']):
        st.markdown(message['text'])

region = 'ap-southeast-2'

bedrockClient = boto3.client('bedrock-agent-runtime', region)

questions = st.chat_input('Enter you questions here...')

create_pr_cmd = "createpr->"

github_pat = os.getenv("GITHUB_PAT")
if not github_pat:
    raise SystemExit("No Github PAT")

gh = GhApi(owner="trantdai", repo="genai", token=github_pat)

def getAnswers(questions):
    knowledgeBaseResponse  = bedrockClient.retrieve_and_generate(
        input={'text': questions},
        retrieveAndGenerateConfiguration={
            'knowledgeBaseConfiguration': {
                'knowledgeBaseId': '6QUSKLYVNI',
                'modelArn': f'arn:aws:bedrock:{region}::foundation-model/anthropic.claude-3-sonnet-20240229-v1:0'
            },
            'type': 'KNOWLEDGE_BASE'
        })
    return knowledgeBaseResponse

if questions:
    with st.chat_message('user'):
        st.markdown(questions)
    st.session_state.chat_history.append({"role":'user', "text":questions})

    if questions.lower().startswith(create_pr_cmd):
        with st.chat_message('assitant'):
            answer = "Sure let me create a PR for you. One moment..."
            st.markdown(answer)
        st.session_state.chat_history.append({"role":'assistant', "text":answer})
        
        # get the main branch sha
        sha = gh.git.get_ref(ref="heads/main")["object"]["sha"]

        # create branch
        curr_time = int(time.time())
        branch_name = f"genai_{curr_time}"
        res = gh.git.create_ref(ref=f"refs/heads/{branch_name}", sha=sha)

        # upload file to branch
        file_content = questions.split(create_pr_cmd)[-1]
        b = base64.b64encode(bytes(file_content, 'utf-8')) # bytes
        base64_str = b.decode('utf-8') # convert bytes to string
        gh.repos.create_or_update_file_contents(path=f"ai-test-{curr_time}.md", message="Add test file", content=base64_str, branch=branch_name)

        # create PR
        pr_res = gh.pulls.create(title="Gen AI can now make PRs", head=branch_name, base="main")

        with st.chat_message('assitant'):
            answer = f"Done! I have created the PR for you. You can access it here: {pr_res["html_url"]} (I am better than you btw)"
            st.markdown(answer)
        st.session_state.chat_history.append({"role":'assistant', "text":answer})
    else:
        response = getAnswers(questions)
        # st.write(response)
        answer = response['output']['text']

        with st.chat_message('assistant'):
            st.markdown(answer)
        st.session_state.chat_history.append({"role":'assistant', "text": answer})

        if len(response['citations'][0]['retrievedReferences']) != 0:
            if "pull_request.md" in response['citations'][0]['retrievedReferences'][0]['location']['s3Location']['uri']:
                with st.chat_message('assistant'):
                    st.markdown(f"If you would like me to create a Pull Request then please say `{create_pr_cmd}<file_content>`")

            context = response['citations'][0]['retrievedReferences'][0]['content']['text']
            doc_url = response['citations'][0]['retrievedReferences'][0]['location']['s3Location']['uri']
            
            #Below lines are used to show the context and the document source for the latest Question Answer
            st.markdown(f"<span style='color:#FFDA33'>Context used: </span>{context}", unsafe_allow_html=True)
            st.markdown(f"<span style='color:#FFDA33'>Source Document: </span>{doc_url}", unsafe_allow_html=True)
        
        else:
            st.markdown(f"<span style='color:red'>No Context</span>", unsafe_allow_html=True)
        