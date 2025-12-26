def move_to_trash(service, message_id):
    """
    Move email to trash using Gmail API
    """
    try:
        service.users().messages().trash(
            userId="me",
            id=message_id
        ).execute()
        return True
    except Exception as e:
        print(f"Error moving to trash: {e}")
        return False
