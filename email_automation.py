import time
from typing import Dict, Any, Optional
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph, END
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib
import imaplib
import email
from email.header import decode_header
from email.utils import parseaddr
import os
import re
from dotenv import load_dotenv
#from IPython.display import display,Image 
import logging

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('email_automation.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
logger.debug("Loaded environment variables from .env file")

# Retrieve environment variables
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
IMAP_SERVER = os.getenv("IMAP_SERVER", "imap.gmail.com")
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
IMAP_FOLDER = os.getenv("IMAP_FOLDER", "[Gmail]/Primary")  # Target Primary tab
EMAIL = os.getenv("EMAIL")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")  # App password for Gmail
SALESPERSON_EMAILS = [
    os.getenv("SALESPERSON_1_EMAIL"),
    os.getenv("SALESPERSON_2_EMAIL"),
    os.getenv("SALESPERSON_3_EMAIL")
]
CC_EMAIL_1 = os.getenv("CC_EMAIL_1", "cc1@digitalpiloto.com")
CC_EMAIL_2 = os.getenv("CC_EMAIL_2", "cc2@digitalpiloto.com")

# Validate required environment variables
if not all([OPENAI_API_KEY, EMAIL, EMAIL_PASSWORD, *SALESPERSON_EMAILS, CC_EMAIL_1, CC_EMAIL_2]):
    logger.error("Missing required environment variables")
    raise ValueError("Missing required environment variables")
logger.debug("Validated environment variables: EMAIL=%s, SALESPERSON_EMAILS=%s, CC_EMAILS=%s", 
             EMAIL, SALESPERSON_EMAILS, [CC_EMAIL_1, CC_EMAIL_2])

# Service-to-questionnaire mapping
SERVICE_QUESTIONNAIRES = {
    "digital marketing": "https://www.digitalpiloto.com/digital-marketing-questionnaire/",
    "web development": "https://www.digitalpiloto.com/web-development-questionnaire/",
    "logo design": "https://www.digitalpiloto.com/logo-design-questionnaire/",
    "ppc": "https://www.digitalpiloto.com/ppc-questionnaire/"
}

# File to store the current salesperson index
COUNTER_FILE = "salesperson_counter.txt"

# Initialize LLM
try:
    llm = ChatOpenAI(model="gpt-4o-mini", api_key=OPENAI_API_KEY)
    logger.debug("Initialized OpenAI LLM (GPT-4o-mini) successfully")
except Exception as e:
    logger.error("Failed to initialize OpenAI LLM: %s", str(e))
    raise

# State definition for the multi-agent system
class AgentState(Dict[str, Any]):
    emails: list
    current_index: int
    notification: Optional[str]
    is_valid_lead: bool
    email_id: Optional[str]
    raw_email: Optional[bytes]
    service: Optional[str]
    questionnaire_url: Optional[str]
    reply_content: Optional[str]
    cc_recipient: list
    salesperson_email: Optional[str]

# Get the current salesperson index
def get_salesperson_index() -> int:
    try:
        if os.path.exists(COUNTER_FILE):
            with open(COUNTER_FILE, "r") as f:
                index = int(f.read().strip())
                logger.debug("Read salesperson index: %d", index)
                return index
        logger.debug("No counter file found, starting at index 0")
        return 0
    except Exception as e:
        logger.error("Error reading salesperson index: %s", str(e))
        return 0

# Update the salesperson index
def update_salesperson_index(current_index: int) -> int:
    next_index = (current_index + 1) % len(SALESPERSON_EMAILS)
    try:
        with open(COUNTER_FILE, "w") as f:
            f.write(str(next_index))
        logger.debug("Updated salesperson index to: %d", next_index)
        return next_index
    except Exception as e:
        logger.error("Error updating salesperson index: %s", str(e))
        return next_index

def check_new_emails():
    logger.debug("Checking for new emails in Gmail Primary tab")
    try:
        mail = imaplib.IMAP4_SSL(IMAP_SERVER)
        logger.debug("Connected to IMAP server: %s", IMAP_SERVER)
        mail.login(EMAIL, EMAIL_PASSWORD)
        logger.debug("Logged in to Gmail IMAP")
        mail.select(IMAP_FOLDER)
        status, data = mail.search(None, '(UNSEEN X-GM-RAW "category:primary")')
        logger.debug("IMAP search status: %s, found %d emails", status, len(data[0].split()))
        emails = []
        for num in data[0].split()[:1]:  # Process one email at a time
            status, msg_data = mail.fetch(num, '(RFC822 UID)')
            raw_email = msg_data[0][1]
            msg = email.message_from_bytes(raw_email)
            uid_data = msg_data[0][0].decode().split()
            uid = uid_data[2] if len(uid_data) > 2 else num.decode()
            subject = decode_header(msg["Subject"])[0][0]
            subject = subject.decode() if isinstance(subject, bytes) else subject
            from_addr = parseaddr(msg["From"])[1]
            from_name = parseaddr(msg["From"])[0] or from_addr.split("@")[0].capitalize()
            reply_to = parseaddr(msg.get("Reply-To", ""))[1] if msg.get("Reply-To") else None
            cc_addrs = parseaddr(msg.get("Cc", ""))[1].split(", ") if msg.get("Cc") else []
            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        body = part.get_payload(decode=True).decode('utf-8', errors='replace')
                        break
                    elif part.get_content_type() == "text/html":
                        body = part.get_payload(decode=True).decode('utf-8', errors='replace').replace('<br>', '\n').replace('</p>', '\n')
                        break
            else:
                body = msg.get_payload(decode=True).decode('utf-8', errors='replace')
            # Enhanced body cleaning
            body = re.sub(r'^Subject:.*\n?', '', body, flags=re.MULTILINE | re.IGNORECASE)
            body = re.sub(r'^-{2,}\s*Forwarded message\s*-{2,}', '', body, flags=re.IGNORECASE)
            body = re.sub(r'^From:.*\n?', '', body, flags=re.MULTILINE | re.IGNORECASE)
            body = re.sub(r'^Sent:.*\n?', '', body, flags=re.MULTILINE | re.IGNORECASE)
            body = re.sub(r'^To:.*\n?', '', body, flags=re.MULTILINE | re.IGNORECASE)
            body = re.sub(r'^Cc:.*\n?', '', body, flags=re.MULTILINE | re.IGNORECASE)
            body = re.sub(r'^Date:.*\n?', '', body, flags=re.MULTILINE | re.IGNORECASE)
            body = re.sub(r'[\*_]+', '', body)
            body = re.sub(r'\n\s*\n', '\n', body)
            body = body.strip()
            # Extract sender name from body
            sender_name_match = re.search(r'Name\s*:\s*([A-Za-z]+)\s*', body, re.IGNORECASE)
            from_name = sender_name_match.group(1).strip() if sender_name_match else from_name
            # Extract TYPE OF PROJECT
            project_type = ""
            match = re.search(r"TYPE OF PROJECT\s*:\s*([^\n]+)", body, re.IGNORECASE)
            if match:
                project_type = match.group(1).strip()
                project_type = re.sub(r'[\*_]+', '', project_type)
            # Extract email address from body
            email_match = re.search(r'(?:Email|Contact)\s*:\s*([\w\.-]+@[\w\.-]+\.\w+)', body, re.IGNORECASE)
            body_email = email_match.group(1) if email_match else None
            if body_email:
                logger.info(f"Found email in body: {body_email}. Using it instead of From header: {from_addr}")
            recipient_email = body_email or reply_to or from_addr
            emails.append({
                "subject": subject,
                "from": recipient_email,
                "from_name": from_name,
                "cc": cc_addrs,
                "body": body,
                "project_type": project_type,
                "original_from": from_addr,
                "uid": uid,
                "raw_email": raw_email
            })
            logger.debug("Fetched email: Subject=%s, From=%s, UID=%s", subject, recipient_email, uid)
        mail.logout()
        logger.debug("Logged out from Gmail IMAP")
        return emails
    except imaplib.IMAP4.error as e:
        logger.error("IMAP error: %s. Check EMAIL and EMAIL_PASSWORD or Gmail IMAP settings.", str(e))
        raise
    except Exception as e:
        logger.error("Error checking emails: %s", str(e))
        return []

# Email monitoring node
def email_monitor(state: AgentState) -> AgentState:
    logger.debug("Starting email monitoring")
    try:
        new_emails = check_new_emails()
        if new_emails:
            logger.info("New email(s) detected in Primary tab: %d", len(new_emails))
            state["emails"] = new_emails
            state["email_id"] = new_emails[0]["uid"]
            state["raw_email"] = new_emails[0]["raw_email"]
            state["cc_recipient"] = new_emails[0].get("cc", []) + [CC_EMAIL_1, CC_EMAIL_2]
            state["notification"] = f"New email received in Primary tab from {new_emails[0]['from_name']} ({new_emails[0]['from']}) at {time.ctime()}"
            logger.info(state["notification"])
        else:
            state["notification"] = "No new emails in Primary tab."
            state["emails"] = []
            state["email_id"] = None
            state["raw_email"] = None
            state["cc_recipient"] = []
            logger.info("No new emails found in Primary tab")
    except Exception as e:
        logger.error("Error in email_monitor: %s", str(e))
        state["notification"] = f"Failed to monitor emails: {str(e)}"
    logger.debug("Email monitor state: %s", state)
    return state

# Lead classification node
def classify_lead(state: AgentState) -> AgentState:
    logger.debug("Classifying lead")
    try:
        if state.get("emails"):
            email = state["emails"][-1]
            prompt = ChatPromptTemplate.from_messages([
                ("system",
                 """
                Analyze the following email content to determine if it is a 'valid' lead, 'spam', or 'test' email.

                **Criteria**:
                - **Valid Lead**: Genuine business inquiry requesting services (e.g., digital marketing, SEO, SMO) with clear intent, no promotional content, and professional tone.
                  Example: "i need all service of DM" with fields like TYPE OF PROJECT: Digital Marketing, WHAT DO YOU NEED: SEO, SMO, Paid Ads, CRO, Content.
                - **Spam Lead**: Unsolicited promotions, offering services (e.g., AI automation), exaggerated claims (e.g., "excel your revenue upto 1000x"), or informal tone with emojis.
                  Example: Offering AI automation services with phrases like "Curiously waiting for your reply🥰😊".
                - **Test Lead**: Emails from internal/test accounts (e.g., email addresses containing 'digitalpiloto' or similar domains) or containing test-related keywords (e.g., 'test', 'AI Development' from internal sources).
                  Example: Email from biswajitdasdigitalpiloto@gmail.com with message "we need service for AI Development."

                Return only 'valid', 'spam', or 'test'.

                Email Content: {body}
                Subject: {subject}
                From: {from_addr}"""),
                MessagesPlaceholder(variable_name="messages")
            ])
            chain = prompt | llm
            classification = chain.invoke({
                "messages": [],
                "body": email["body"],
                "subject": email["subject"],
                "from_addr": email["from"]
            }).content.strip().lower()
            state["is_valid_lead"] = classification == "valid"
            logger.debug("Classified as: %s", classification)
            state["notification"] = f"Email from {email['from_name']} classified as {classification}."
            logger.info(state["notification"])
        else:
            state["is_valid_lead"] = False
            state["notification"] = "No emails to classify."
            logger.info(state["notification"])
    except Exception as e:
        logger.error("Error classifying lead: %s", str(e))
        state["is_valid_lead"] = False
        state["notification"] = f"Failed to classify email: {str(e)}"
    logger.debug("Classify lead state: %s", state)
    return state

# Service identification node
def identify_service(state: AgentState) -> AgentState:
    logger.debug("Identifying service for lead")
    try:
        if state.get("is_valid_lead") and state.get("emails"):
            email = state["emails"][-1]
            prompt = ChatPromptTemplate.from_messages([
                ("system", """
                 Analyze the following email content and TYPE OF PROJECT to identify the service the client is requesting. 
                 Choose from: Digital Marketing, Web Development, Logo Design, PPC. If unsure or the service is not listed (e.g., AI Development), default to Digital Marketing. 
                 Return only the service name.

                Email Content: {body}
                TYPE OF PROJECT: {project_type}"""),
                MessagesPlaceholder(variable_name="messages")
            ])
            chain = prompt | llm
            service = chain.invoke({
                "messages": [],
                "body": email["body"],
                "project_type": email.get("project_type", "")
            }).content.strip()
            state["service"] = service if service.lower() in SERVICE_QUESTIONNAIRES else "Digital Marketing"
            state["questionnaire_url"] = SERVICE_QUESTIONNAIRES.get(state["service"].lower(), SERVICE_QUESTIONNAIRES["digital marketing"])
            logger.debug("Identified service: %s, Questionnaire URL: %s", state["service"], state["questionnaire_url"])
        else:
            state["service"] = "Digital Marketing"
            state["questionnaire_url"] = SERVICE_QUESTIONNAIRES["digital marketing"]
            logger.info("No valid lead or emails, defaulting to Digital Marketing")
    except Exception as e:
        logger.error("Error identifying service: %s", str(e))
        state["service"] = "Digital Marketing"
        state["questionnaire_url"] = SERVICE_QUESTIONNAIRES["digital marketing"]
    logger.debug("Identify service state: %s", state)
    return state

def forward_email_node(state: AgentState) -> AgentState:
    logger.debug("Starting email forwarding")
    try:
        if state.get("emails") and state.get("is_valid_lead") and state.get("raw_email"):
            email_data = state["emails"][-1]
            raw_email = state["raw_email"]
            salesperson_email = SALESPERSON_EMAILS[state["current_index"]]
            state["salesperson_email"] = salesperson_email
            cc_recipient = state.get("cc_recipient", [])
            logger.info("Forwarding lead from %s to %s with CC: %s", email_data['from'], salesperson_email, cc_recipient)
            msg = email.message_from_bytes(raw_email)
            forward_msg = MIMEMultipart()
            forward_msg["Subject"] = msg["Subject"]
            forward_msg["From"] = EMAIL
            forward_msg["To"] = salesperson_email
            forward_msg["Cc"] = ", ".join([cc for cc in cc_recipient if cc])
            forward_msg["Reply-To"] = email_data["from"]
            if msg.is_multipart():
                html_part_found = False
                for part in msg.walk():
                    content_type = part.get_content_type()
                    content_disposition = str(part.get("Content-Disposition"))
                    if content_type == "text/html" and "attachment" not in content_disposition:
                        payload = part.get_payload(decode=True)
                        if payload:
                            charset = part.get_content_charset() or 'utf-8'
                            try:
                                body = payload.decode(charset, errors='replace')
                                forward_msg.attach(MIMEText(body, 'html', charset))
                                html_part_found = True
                            except Exception as e:
                                logger.error("Error decoding HTML payload: %s", str(e))
                                forward_msg.attach(MIMEText(payload.decode('utf-8', errors='replace'), 'html', 'utf-8'))
                if not html_part_found and msg.get_content_type() == "text/plain":
                    payload = msg.get_payload(decode=True)
                    if payload:
                        charset = msg.get_content_charset() or 'utf-8'
                        try:
                            body = payload.decode(charset, errors='replace')
                            forward_msg.attach(MIMEText(body, 'html', charset))
                        except Exception as e:
                            logger.error("Error decoding fallback payload: %s", str(e))
                            forward_msg.attach(MIMEText(payload.decode('utf-8', errors='replace'), 'html', 'utf-8'))
            else:
                payload = msg.get_payload(decode=True)
                if payload:
                    charset = msg.get_content_charset() or 'utf-8'
                    try:
                        body = payload.decode(charset, errors='replace')
                        forward_msg.attach(MIMEText(body, 'html', charset))
                    except Exception as e:
                        logger.error("Error decoding payload: %s", str(e))
                        forward_msg.attach(MIMEText(payload.decode('utf-8', errors='replace'), 'html', 'utf-8'))
            with smtplib.SMTP(SMTP_SERVER, 587) as server:
                server.starttls()
                server.login(EMAIL, EMAIL_PASSWORD)
                logger.debug("Logged in to Gmail SMTP")
                server.send_message(forward_msg)
            logger.info("Email forwarded to %s with CC: %s from %s", salesperson_email, cc_recipient, email_data['from'])
            state["current_index"] = update_salesperson_index(state["current_index"])
            state["notification"] = f"Lead forwarded to {salesperson_email} at {time.ctime()}"
            logger.info(state["notification"])
        else:
            state["notification"] = "Email skipped (not a valid lead or missing raw email)."
            logger.info(state["notification"])
    except smtplib.SMTPAuthenticationError as e:
        logger.error("SMTP authentication failed: %s. Check EMAIL_PASSWORD or Gmail security settings.", str(e))
        state["notification"] = "Failed to forward lead due to authentication error."
    except Exception as e:
        logger.error("Error forwarding email: %s", str(e))
        state["notification"] = "Failed to forward lead."
    logger.debug("Forward email state: %s", state)
    return state

def draft_and_send_reply(state: AgentState) -> AgentState:
    logger.debug("Drafting and sending reply")
    try:
        if state.get("is_valid_lead") and state.get("emails") and state.get("questionnaire_url"):
            email = state["emails"][-1]
            questionnaire_url = state["questionnaire_url"]
            prompt = ChatPromptTemplate.from_messages([
                ("system", """Draft a friendly email reply strictly following this structure, using only the provided sender name, service, and questionnaire URL. Do not include the subject line, original email content, or any additional text:

                Dear {sender_name},

                Thanks for reaching out!

                To help us better understand your specific needs and business objectives, we kindly request you to complete our {service} Questionnaire: 
                👉 {questionnaire_url}

                Your responses will help us better understand your needs, enabling us to recommend the most effective strategies tailored to your goals.

                We’re also happy to inform you that your inquiry has been assigned to our Senior Management Consultant, XYZ. He will be in touch with you shortly. In the meantime, feel free to contact him directly at +91 xxxxx xxxxx.

                We'd like to invite you to explore our social media pages and company profile to gain a deeper understanding of our creative work, marketing strategies, results, and client feedback:

                - Company Profile: https://drive.google.com/file/d/1rRfqjYl2w_o2MZxlh5pq07MIEbT-pQGG/view
                - Google Partners Company: https://www.google.com/partners/agency?id=8986533424
                - Our social media links:
                  - https://www.facebook.com/digitalpiloto/
                  - https://www.instagram.com/digitalpiloto/
                  - https://in.linkedin.com/company/digitalpiloto
                  - https://www.youtube.com/c/DigitalPiloto
                - Our Client's Testimonials: https://youtube.com/playlist?list=PLBEL8dvxcufkAvStEwSAkQO-0dbATbeZp&si=_wpy8USjSdfVVw3R

                Additionally, please let us know a suitable time for a Google Meet. We’d love to learn more about your requirements and discuss how we can support you in the best possible way.

                Looking forward to a great and long collaboration!

                Best regards,
                Your Name
                Digital Piloto"""),
                MessagesPlaceholder(variable_name="messages")
            ])
            chain = prompt | llm
            state["reply_content"] = chain.invoke({
                "messages": [],
                "sender_name": email["from_name"],
                "service": state["service"],
                "questionnaire_url": questionnaire_url
            }).content.strip()
            logger.info(f"Drafted reply to {email['from']} successfully.")
            # Add salesperson_email to cc_recipient for the reply if it exists and not already included
            cc_recipient = state.get("cc_recipient", [])
            salesperson_email = state.get("salesperson_email")
            if salesperson_email and salesperson_email not in cc_recipient:
                cc_recipient.append(salesperson_email)
            send_email(
                recipient=email["from"],
                cc_recipient=cc_recipient,
                content=state["reply_content"],
                subject=f"Re: {email['subject']}"
            )
            state["notification"] = f"Reply sent successfully to {email['from']} at {time.ctime()}"
            logger.info(state["notification"])
            # Mark email as seen only after both forwarding and replying succeed
            if state.get("email_id"):
                mark_email_seen(state["email_id"])
        else:
            state["notification"] = f"No reply sent (is_valid_lead={state.get('is_valid_lead')}, emails={bool(state.get('emails'))}, questionnaire_url={bool(state.get('questionnaire_url'))})."
            logger.info(state["notification"])
            if state.get("email_id"):
                mark_email_seen(state["email_id"])
    except Exception as e:
        logger.error(f"Error in draft_and_send_reply: {str(e)}")
        state["notification"] = f"Failed to send reply: {str(e)}"
        if state.get("email_id"):
            mark_email_seen(state["email_id"])
    logger.debug("Draft and send reply state: %s", state)
    state["emails"] = []
    state["raw_email"] = None
    return state

def send_email(recipient: str, cc_recipient: list, content: str, subject: str):
    try:
        if not re.match(r'[\w\.-]+@[\w\.-]+\.\w+', recipient):
            raise ValueError(f"Invalid recipient email: {recipient}")
        msg = MIMEText(content)
        msg["Subject"] = subject
        msg["From"] = EMAIL
        msg["To"] = recipient
        if cc_recipient:
            msg["Cc"] = ", ".join([cc for cc in cc_recipient if cc])
        with smtplib.SMTP(SMTP_SERVER, 587) as server:
            server.starttls()
            server.login(EMAIL, EMAIL_PASSWORD)
            server.send_message(msg)
        logger.info(f"Email sent to {recipient} with CC: {', '.join(cc_recipient) if cc_recipient else 'None'}")
    except Exception as e:
        logger.error(f"Failed to send email to {recipient}: {str(e)}")
        raise

def mark_email_seen(uid: str):
    if uid:
        try:
            mail = imaplib.IMAP4_SSL(IMAP_SERVER)
            mail.login(EMAIL, EMAIL_PASSWORD)
            mail.select(IMAP_FOLDER)
            mail.uid('STORE', uid, '+FLAGS', '\\Seen')
            logger.debug("Marked email UID %s as seen", uid)
            mail.logout()
        except Exception as e:
            logger.error("Error marking email as seen: %s", str(e))

# Conditional edge logic
def decide_next(state: AgentState) -> str:
    logger.debug("Deciding next step: is_valid_lead=%s, notification=%s", state.get("is_valid_lead"), state.get("notification"))
    if state.get("notification") and "No new emails" in state["notification"]:
        return "end"
    if state.get("is_valid_lead"):
        return "identify_service"
    return "end"

# Build the LangGraph workflow
workflow = StateGraph(AgentState)
workflow.add_node("email_monitor", email_monitor)
workflow.add_node("classify_lead", classify_lead)
workflow.add_node("identify_service", identify_service)
workflow.add_node("forward_email", forward_email_node)
workflow.add_node("draft_and_send_reply", draft_and_send_reply)

# Define edges
workflow.add_edge("email_monitor", "classify_lead")
workflow.add_conditional_edges(
    "classify_lead",
    decide_next,
    {
        "identify_service": "identify_service",
        "end": END
    }
)
workflow.add_edge("identify_service", "forward_email")
workflow.add_edge("forward_email", "draft_and_send_reply")
workflow.add_edge("draft_and_send_reply", END)

# Set entry point
workflow.set_entry_point("email_monitor")

# Compile the workflow
app = workflow.compile()
logger.debug("LangGraph workflow compiled")

#display(Image(app.get_graph().draw_mermaid_png(output_file_path="tutor_agent.png")))
# Main execution loop
def main():
    logger.info("Starting email automation loop")
    initial_state = AgentState(
        emails=[],
        current_index=get_salesperson_index(),
        notification=None,
        is_valid_lead=False,
        email_id=None,
        raw_email=None,
        service=None,
        questionnaire_url=None,
        reply_content=None,
        cc_recipient=[],
        salesperson_email=None
    )
    try:
        while True:
            logger.debug("Starting new workflow cycle at %s", time.ctime())
            try:
                final_state = app.invoke(initial_state)
                logger.info("Workflow cycle completed: %s", final_state['notification'])
                initial_state["current_index"] = final_state["current_index"]
            except Exception as e:
                logger.error("Workflow cycle failed: %s", str(e))
            logger.debug("Waiting 30 seconds before next cycle")
            #time.sleep(30)
    except KeyboardInterrupt:
        logger.info("Script terminated by user")
        return

if __name__ == "__main__":
    main()